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
INVITE_SPAM_WINDOW_SECONDS = 30
INVITE_SPAM_THRESHOLD = 5
INVITE_TIMEOUT_HOURS = 1

# Anti-Webhook Settings
WEBHOOK_STRIKES_BEFORE_KICK = 3

# Anti Ban/Kick Spamm Settings
ANTI_BAN_KICK_WINDOW_SECONDS = 30
ANTI_BAN_KICK_THRESHOLD = 3

# Anti Mention Spam Settings
MENTION_SPAM_WINDOW_SECONDS = 15
MENTION_SPAM_THRESHOLD = 3

VERBOSE = True

# ---------- Bot & Intents ----------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True
intents.bans = True
intents.presences = True
intents.webhooks = True
intents.guild_messages = True
intents.guild_reactions = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ---------- Hilfsfunktionen ----------
INVITE_REGEX = re.compile(
    r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[A-Za-z0-9\-]+",
    re.IGNORECASE,
)

whitelists: dict[int, set[int]] = defaultdict(set)
blacklists: dict[int, set[int]] = defaultdict(set)

invite_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=50))
webhook_strikes: defaultdict[int, int] = defaultdict(int)
existing_webhooks: dict[int, set[int]] = defaultdict(set)

# Anti Ban/Kick Spamm Speicher
ban_kick_actions: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))

# Anti Mention Spam Speicher
mention_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
mention_messages: dict[int, deque[discord.Message]] = defaultdict(lambda: deque(maxlen=10))

def log(*args):
    if VERBOSE:
        print("[LOG]", *args)

async def safe_delete_message(msg: discord.Message):
    try:
        await msg.delete()
    except (NotFound, Forbidden, HTTPException):
        pass

def is_whitelisted(member: discord.Member | discord.User) -> bool:
    gid = getattr(getattr(member, "guild", None), "id", None)
    if gid is None:
        return False
    return member.id in whitelists[gid]

> bool:
    return ctx.author.id == BOT_ADMIN_ID or (ctx.guild and ctx.author.id == ctx.guild.owner_id)

async def kick_member(guild: discord.Guild, member: discord.Member | discord.User, reason: str):
    if not member or (isinstance(member, discord.Member) and is_whitelisted(member)):
        return
    if member.id == bot.user.id:
        return
    try:
        await guild.kick(discord.Object(id=member.id), reason=reason)
        log(f"Kicked {member} | Reason: {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Kick failed for {member}: {e}")

async def ban_member(guild: discord.Guild, member: discord.Member | discord.User, reason: str, delete_days: int = 0):
    if not member or (isinstance(member, discord.Member) and is_whitelisted(member)):
        return
    if member.id == bot.user.id:
        return
    try:
        await guild.ban(discord.Object(id=member.id), reason=reason, delete_message_days=delete_days)
        log(f"Banned {member} | Reason: {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Ban failed for {member}: {e}")

async def timeout_member(member: discord.Member, hours: int, reason: str):
    if not member or is_whitelisted(member):
        return
    if member.id == bot.user.id:
        return
    try:
        until = datetime.now(timezone.utc) + timedelta(hours=hours)
        await member.edit(timed_out_until=until, reason=reason)
        log(f"Timed out {member} until {until} | Reason: {reason}")
    except (Forbidden, HTTPException, NotFound) as e:
        log(f"Timeout failed for {member}: {e}")

async def actor_from_audit_log(guild: discord.Guild, action: AuditLogAction, target_id: int | None = None, within_seconds: int = 10):
    await asyncio.sleep(0.5)
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
    except NotFound:
        log(f"Audit Log Fehler: Guild {guild.id} nicht gefunden.")
    except HTTPException as e:
        log(f"Audit Log HTTP-Fehler: {e}")
    return None

# ---------- Events ----------
@bot.event
async def on_ready():
    log(f"Bot online als {bot.user} (ID: {bot.user.id})")
    try:
        await bot.tree.sync()
        log("Slash Commands global synchronisiert 🌍")
    except Exception as e:
        log(f"Fehler beim Slash Command Sync: {e}")
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Game("Bereit zum Beschützen!")
    )

# ---------- Anti Ban/Kick Spamm ----------
async def track_ban_kick(actor: discord.Member, action_type: str):
    now = asyncio.get_event_loop().time()
    dq = ban_kick_actions[actor.id]
    dq.append(now)
    while dq and (now - dq[0]) > ANTI_BAN_KICK_WINDOW_SECONDS:
        dq.popleft()
    if len(dq) >= ANTI_BAN_KICK_THRESHOLD:
        guild = actor.guild
        await kick_member(guild, actor, f"Anti Ban/Kick Spamm: {len(dq)} Aktionen in kurzer Zeit")
        ban_kick_actions[actor.id].clear()

@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    actor = await actor_from_audit_log(guild, AuditLogAction.ban, target_id=user.id, within_seconds=30)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await track_ban_kick(actor, "ban")

@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.kick, target_id=member.id, within_seconds=30)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await track_ban_kick(actor, "kick")

# ---------- Anti Webhook / Anti Invite / Anti Mention Spam ----------
@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # --- Anti Invite Spam ---
    if INVITE_REGEX.search(message.content):
        if not is_whitelisted(message.author):
            await safe_delete_message(message)
            now_ts = asyncio.get_event_loop().time()
            dq = invite_timestamps[message.author.id]
            dq.append(now_ts)
            while dq and (now_ts - dq[0]) > INVITE_SPAM_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) >= INVITE_SPAM_THRESHOLD:
                await kick_member(message.guild, message.author, "Invite-Link-Spam (Kick nach 5 Links in 30s)")
                invite_timestamps[message.author.id].clear()

    # --- Anti Mention Spam ---
    if not is_whitelisted(message.author):
        if message.mention_everyone or any(role.mentionable for role in message.role_mentions):
            now_ts = asyncio.get_event_loop().time()
            dq = mention_timestamps[message.author.id]
            msg_list = mention_messages[message.author.id]
            dq.append(now_ts)
            msg_list.append(message)

            while dq and (now_ts - dq[0]) > MENTION_SPAM_WINDOW_SECONDS:
                dq.popleft()
                if msg_list:
                    msg_list.popleft()

            if len(dq) >= MENTION_SPAM_THRESHOLD:
                await kick_member(
                    message.guild,
                    message.author,
                    f"Massenping-Spam: {len(dq)} @everyone/@here/@Role Erwähnungen in kurzer Zeit"
                )
                for msg in list(msg_list):
                    await safe_delete_message(msg)
                mention_timestamps[message.author.id].clear()
                mention_messages[message.author.id].clear()

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
            continue
        existing_webhooks[guild.id].add(hook.id)
        member = guild.get_member(hook.user.id) if hook.user and isinstance(hook.user, discord.User) else None
        if member and is_whitelisted(member):
            continue
        try:
            await hook.delete(reason="Anti-Webhook aktiv")
            log(f"Webhook {hook.name} gelöscht in #{channel.name}")
        except (Forbidden, HTTPException, NotFound):
            pass
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        webhook_strikes[actor.id] += 1
        if webhook_strikes[actor.id] >= WEBHOOK_STRIKES_BEFORE_KICK:
            await kick_member(guild, actor, "Zu viele Webhook-Erstellungen (3)")
            webhook_strikes[actor.id] = 0

# ---------- Anti Bot Join ----------
@bot.event
async def on_member_join(member: discord.Member):
    if member.bot:
        inviter = None
        try:
            async for entry in member.guild.audit_logs(limit=10, action=AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    break
        except Exception:
            pass
        if inviter and not is_whitelisted(inviter):
            await kick_member(member.guild, member, "Bot wurde von nicht-whitelisted User eingeladen")
            await kick_member(member.guild, inviter, "Bot eingeladen ohne Whitelist-Berechtigung")

# ---------- Anti Role/Channel Delete ----------
@bot.event
async def on_guild_channel_delete(channel):
    actor = await actor_from_audit_log(channel.guild, AuditLogAction.channel_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(channel.guild, actor, "Rolle/Kanal gelöscht ohne Berechtigung")

@bot.event
async def on_guild_role_delete(role):
    actor = await actor_from_audit_log(role.guild, AuditLogAction.role_delete, within_seconds=10)
    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        await kick_member(role.guild, actor, "Rolle/Kanal gelöscht ohne Berechtigung")

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
        try:
            user = ctx.guild.get_member(uid) or await bot.fetch_user(uid)
            resolved.append(user.name if user else str(uid))
        except Exception:
            resolved.append(str(uid))
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
        try:
            user = ctx.guild.get_member(uid) or await bot.fetch_user(uid)
            resolved.append(user.name if user else str(uid))
        except Exception:
            resolved.append(str(uid))
    await ctx.reply("🚫 Blacklist:\n" + "\n".join(resolved))

# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)

