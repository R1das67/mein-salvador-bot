import os 
import re
import asyncio
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import discord
from discord import AuditLogAction, Forbidden, HTTPException, NotFound
from discord.ext import commands

# ---------- Konfiguration ----------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
BOT_ADMIN_ID = 843180408152784936

# Invite-Settings
INVITE_SPAM_WINDOW_SECONDS = 20
INVITE_SPAM_THRESHOLD = 5
INVITE_TIMEOUT_HOURS = 1

# Anti-Webhook Settings
WEBHOOK_STRIKES_BEFORE_KICK = 3

VERBOSE = True

# ---------- Bot & Intents ----------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True
intents.bans = True
intents.presences = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- Hilfsfunktionen ----------
INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[A-Za-z0-9\-]+",
    re.IGNORECASE,
)

whitelists: dict[int, set[int]] = defaultdict(set)  # key = guild.id
blacklists: dict[int, set[int]] = defaultdict(set)

invite_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=50))
webhook_strikes: defaultdict[int, int] = defaultdict(int)

# Store existing webhooks to know which ones existed before bot start
existing_webhooks: dict[int, set[int]] = defaultdict(set)

def log(*args):
    if VERBOSE:
        print("[LOG]", *args)

async def safe_delete_message(msg: discord.Message):
    try:
        await msg.delete()
    except (NotFound, Forbidden):
        pass

def is_whitelisted(member: discord.Member) -> bool:
    return member and member.id in whitelists[member.guild.id]

def is_blacklisted(member: discord.Member) -> bool:
    return member and member.id in blacklists[member.guild.id]

def is_bot_admin(ctx: commands.Context) -> bool:
    return ctx.author.id == BOT_ADMIN_ID or (ctx.guild and ctx.author.id == ctx.guild.owner_id)

async def kick_member(guild: discord.Guild, member: discord.Member, reason: str):
    if not member or is_whitelisted(member):
        return
    try:
        await guild.kick(member, reason=reason)
        log(f"Kicked {member} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log(f"Kick failed for {member}: {e}")

async def ban_member(guild: discord.Guild, member: discord.Member, reason: str, delete_days: int = 0):
    if not member or is_whitelisted(member):
        return
    try:
        await guild.ban(member, reason=reason, delete_message_days=delete_days)
        log(f"Banned {member} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log(f"Ban failed for {member}: {e}")

async def timeout_member(member: discord.Member, hours: int, reason: str):
    if not member or is_whitelisted(member):
        return
    try:
        until = datetime.now(timezone.utc) + timedelta(hours=hours)
        await member.edit(timed_out_until=until, reason=reason)
        log(f"Timed out {member} until {until} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log(f"Timeout failed for {member}: {e}")

async def actor_from_audit_log(guild: discord.Guild, action: AuditLogAction, target_id: int | None = None, within_seconds: int = 10):
    await asyncio.sleep(1)  # Pause für Audit Log Konsistenz
    try:
        now = datetime.now(timezone.utc)
        async for entry in guild.audit_logs(limit=15, action=action):
            if (now - entry.created_at).total_seconds() > within_seconds:
                continue
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            return entry.user
    except Forbidden:
        log("Keine Berechtigung, Audit-Logs zu lesen.")
    return None

# ---------- Events ----------
@bot.event
async def on_ready():
    log(f"Bot online als {bot.user} (ID: {bot.user.id})")

    # Guild-spezifisches Sync (schneller sichtbar!)
    TEST_GUILD_ID = 1416506382013960363  # Deine Guild-ID hier eintragen
    guild = discord.Object(id=TEST_GUILD_ID)
    await bot.tree.sync(guild=guild)

    log("Slash Commands für Test-Guild synchronisiert ✅")

    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Game("Bereit zum Beschützen!")
    )

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    if INVITE_REGEX.search(message.content):
        if not is_whitelisted(message.author):
            await safe_delete_message(message)
            now_ts = asyncio.get_event_loop().time()
            dq = invite_timestamps[message.author.id]
            dq.append(now_ts)
            while dq and (now_ts - dq[0]) > INVITE_SPAM_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= INVITE_SPAM_THRESHOLD:
                if isinstance(message.author, discord.Member) and message.author.guild_permissions.administrator:
                    await kick_member(message.guild, message.author, "Invite-Link-Spam (Admin)")
                else:
                    await timeout_member(message.author, INVITE_TIMEOUT_HOURS, "Invite-Link-Spam")
                invite_timestamps[message.author.id].clear()
    await bot.process_commands(message)

@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.webhook_create, within_seconds=30)
    try:
        hooks = await channel.webhooks()
    except (Forbidden, HTTPException):
        hooks = []
    for hook in hooks:
        if hook.id in existing_webhooks[guild.id]:
            continue  # Ignoriere Webhooks, die schon vor Botstart existierten
        member = guild.get_member(hook.user.id) if hook.user else None
        if member and is_whitelisted(member):
            continue
        try:
            await hook.delete(reason="Anti-Webhook aktiv")
            log(f"Webhook {hook.name} gelöscht in #{channel.name}")
        except (Forbidden, HTTPException):
            pass
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        webhook_strikes[actor.id] += 1
        if webhook_strikes[actor.id] >= WEBHOOK_STRIKES_BEFORE_KICK:
            await kick_member(guild, actor, "Zu viele Webhook-Erstellungen")
            webhook_strikes[actor.id] = 0

# Anti Ban
@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    actor = await actor_from_audit_log(guild, AuditLogAction.ban, target_id=user.id, within_seconds=20)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(guild, actor, f"Unzulässiges Bannen von {user}")

# Anti Kick
@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.kick, target_id=member.id, within_seconds=20)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(guild, actor, f"Unzulässiges Kicken von {member}")

# Anti Role Delete
@bot.event
async def on_guild_role_delete(role: discord.Role):
    guild = role.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.role_delete, target_id=role.id, within_seconds=20)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(guild, actor, f"Löschen der Rolle '{role.name}'")

# Anti Channel Delete
@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    guild = channel.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.channel_delete, target_id=channel.id, within_seconds=20)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(guild, actor, f"Löschen des Kanals '{channel.name}'")

# Anti Bot Join & Blacklist Check
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild

    # Blacklist Check
    if member.id in blacklists[guild.id]:
        await kick_member(guild, member, "User ist auf der Blacklist")
        return

    # Normale User ignorieren
    if not member.bot:
        return  # Normale User werden hier nicht weiter überprüft

    # Prüfen, wer den Bot eingeladen hat
    inviter = await actor_from_audit_log(guild, AuditLogAction.bot_add, target_id=member.id, within_seconds=60)
    if isinstance(inviter, discord.Member):
        if not is_whitelisted(inviter):
            await ban_member(guild, member, "Anti Bot Join: Bot unerlaubt eingeladen")
            await ban_member(guild, inviter, f"Anti Bot Join: {inviter} hat Bot eingeladen")
        else:
            log(f"Whitelisted inviter {inviter} hat Bot {member} eingeladen – kein Ban.")

# ---------- Commands ----------
@bot.hybrid_command(name="addwhitelist", description="Fügt einen User zur Whitelist hinzu (Owner/Admin Only)")
async def add_whitelist(ctx: commands.Context, user: discord.User):
    if not is_bot_admin(ctx):
        return await ctx.reply("❌ Keine Berechtigung.")
    whitelists[ctx.guild.id].add(user.id)
    await ctx.reply(f"✅ User `{user}` wurde in **{ctx.guild.name}** zur Whitelist hinzugefügt.")

@bot.hybrid_command(name="removewhitelist", description="Entfernt einen User von der Whitelist (Owner/Admin Only)")
async def remove_whitelist(ctx: commands.Context, user: discord.User):
    if not is_bot_admin(ctx):
        return await ctx.reply("❌ Keine Berechtigung.")
    whitelists[ctx.guild.id].discard(user.id)
    await ctx.reply(f"✅ User `{user}` wurde in **{ctx.guild.name}** von der Whitelist entfernt.")

@bot.hybrid_command(name="showwhitelist", description="Zeigt alle User in der Whitelist")
async def show_whitelist(ctx: commands.Context):
    users = whitelists[ctx.guild.id]
    if not users:
        return await ctx.reply("ℹ️ Whitelist ist leer.")
    resolved = []
    for uid in users:
        user = ctx.guild.get_member(uid) or await bot.fetch_user(uid)
        resolved.append(user.name if user else str(uid))
    await ctx.reply("📜 Whitelist:\n" + "\n".join(resolved))

@bot.hybrid_command(name="addblacklist", description="Fügt einen User zur Blacklist hinzu (Owner/Admin Only)")
async def add_blacklist(ctx: commands.Context, user: discord.User):
    if not is_bot_admin(ctx):
        return await ctx.reply("❌ Keine Berechtigung.")
    blacklists[ctx.guild.id].add(user.id)
    await ctx.reply(f"✅ User `{user}` wurde in **{ctx.guild.name}** zur Blacklist hinzugefügt.")

@bot.hybrid_command(name="removeblacklist", description="Entfernt einen User von der Blacklist (Owner/Admin Only)")
async def remove_blacklist(ctx: commands.Context, user: discord.User):
    if not is_bot_admin(ctx):
        return await ctx.reply("❌ Keine Berechtigung.")
    blacklists[ctx.guild.id].discard(user.id)
    await ctx.reply(f"✅ User `{user}` wurde in **{ctx.guild.name}** von der Blacklist entfernt.")

@bot.hybrid_command(name="showblacklist", description="Zeigt alle User in der Blacklist")
async def show_blacklist(ctx: commands.Context):
    users = blacklists[ctx.guild.id]
    if not users:
        return await ctx.reply("ℹ️ Blacklist ist leer.")
    resolved = []
    for uid in users:
        user = ctx.guild.get_member(uid) or await bot.fetch_user(uid)
        resolved.append(user.name if user else str(uid))
    await ctx.reply("🚫 Blacklist:\n" + "\n".join(resolved))

# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)
