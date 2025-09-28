import os
import re
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

import discord
from discord import AuditLogAction, Forbidden, HTTPException, NotFound
from discord.ext import commands

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("GlobexSecurity")

# ---------- Konfiguration ----------
TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
BOT_ADMIN_ID = 843180408152784936

INVITE_SPAM_WINDOW_SECONDS = 20
INVITE_SPAM_THRESHOLD = 5
INVITE_TIMEOUT_HOURS = 1
WEBHOOK_STRIKES_BEFORE_KICK = 3

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

whitelists: dict[int, set[int]] = defaultdict(set)
blacklists: dict[int, set[int]] = defaultdict(set)

def is_whitelisted(member: discord.Member) -> bool:
    return member and member.id in whitelists[member.guild.id]

def is_blacklisted(member: discord.Member) -> bool:
    return member and member.id in blacklists[member.guild.id]

def is_bot_admin(ctx: commands.Context) -> bool:
    return ctx.author.id == BOT_ADMIN_ID or (ctx.guild and ctx.author.id == ctx.guild.owner_id)

async def safe_delete_message(msg: discord.Message):
    try:
        await msg.delete()
    except (NotFound, Forbidden):
        pass

async def kick_member(guild: discord.Guild, member: discord.Member, reason: str):
    if not member or is_whitelisted(member):
        return
    if guild.me.top_role <= member.top_role:
        log.warning(f"Kick fehlgeschlagen: {member} hat gleiche/höhere Rolle.")
        return
    try:
        await guild.kick(member, reason=reason)
        log.info(f"Kicked {member} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log.error(f"Kick failed for {member}: {e}")

async def ban_member(guild: discord.Guild, member: discord.Member, reason: str, delete_days: int = 0):
    if not member or is_whitelisted(member):
        return
    if guild.me.top_role <= member.top_role:
        log.warning(f"Ban fehlgeschlagen: {member} hat gleiche/höhere Rolle.")
        return
    try:
        await guild.ban(member, reason=reason, delete_message_days=delete_days)
        log.info(f"Banned {member} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log.error(f"Ban failed for {member}: {e}")

async def timeout_member(member: discord.Member, hours: int, reason: str):
    if not member or is_whitelisted(member):
        return
    if member.guild.me.top_role <= member.top_role:
        log.warning(f"Timeout fehlgeschlagen: {member} hat gleiche/höhere Rolle.")
        return
    try:
        until = datetime.now(timezone.utc) + timedelta(hours=hours)
        await member.edit(timed_out_until=until, reason=reason)
        log.info(f"Timed out {member} until {until} | Reason: {reason}")
    except (Forbidden, HTTPException) as e:
        log.error(f"Timeout failed for {member}: {e}")

async def actor_from_audit_log(
    guild: discord.Guild, action: AuditLogAction, target_id: int | None = None, within_seconds: int = 10
):
    await asyncio.sleep(1)  # kleine Verzögerung, damit AuditLog nachkommt
    try:
        now = datetime.now(timezone.utc)
        async for entry in guild.audit_logs(limit=10, action=action):
            if (now - entry.created_at).total_seconds() > within_seconds:
                continue
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            return entry.user
    except Forbidden:
        log.warning("Keine Berechtigung, Audit-Logs zu lesen.")
    return None

# ---------- In-Memory Tracker ----------
invite_timestamps: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=50))
webhook_strikes: defaultdict[int, int] = defaultdict(int)

# ---------- Events ----------
@bot.event
async def on_ready():
    log.info(f"Bot online als {bot.user} (ID: {bot.user.id})")
    try:
        synced = await bot.tree.sync()
        log.info(f"{len(synced)} Slash-Commands synchronisiert.")
    except Exception as e:
        log.error(f"Fehler beim Synchronisieren der Commands: {e}")

    await bot.change_presence(status=discord.Status.online, activity=discord.Game("Bereit zum Beschützen!"))

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
                    log.warning(f"Admin {message.author} spammt Invite-Links – Owner benachrichtigen!")
                else:
                    await timeout_member(message.author, INVITE_TIMEOUT_HOURS, "Invite-Link-Spam")
                invite_timestamps[message.author.id].clear()
    await bot.process_commands(message)

@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    guild = channel.guild
    actor = await actor_from_audit_log(guild, AuditLogAction.webhook_create, within_seconds=60)

    try:
        hooks = await channel.webhooks()
    except (Forbidden, HTTPException):
        hooks = []

    for hook in hooks:
        if (datetime.now(timezone.utc) - hook.created_at).total_seconds() <= 60:
            member = guild.get_member(hook.user.id) if hook.user else None
            if member and is_whitelisted(member):
                continue
            try:
                await hook.delete(reason="Anti-Webhook aktiv")
                log.info(f"Webhook {hook.name} gelöscht in #{channel.name}")
            except (Forbidden, HTTPException):
                log.warning(f"Konnte Webhook {hook.name} nicht löschen in #{channel.name}")

    if isinstance(actor, discord.Member) and not is_whitelisted(actor):
        webhook_strikes[actor.id] += 1
        if webhook_strikes[actor.id] >= WEBHOOK_STRIKES_BEFORE_KICK:
            await kick_member(guild, actor, "Zu viele Webhook-Erstellungen")
            webhook_strikes[actor.id] = 0

# ---------- Slash Commands ----------
@bot.tree.command(name="whitelist_add", description="Fügt einen User zur Whitelist hinzu")
async def whitelist_add(interaction: discord.Interaction, user: discord.Member):
    if interaction.user.id != BOT_ADMIN_ID:
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    whitelists[interaction.guild.id].add(user.id)
    await interaction.response.send_message(f"{user.mention} zur Whitelist hinzugefügt.")

@bot.tree.command(name="whitelist_remove", description="Entfernt einen User von der Whitelist")
async def whitelist_remove(interaction: discord.Interaction, user: discord.Member):
    if interaction.user.id != BOT_ADMIN_ID:
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    whitelists[interaction.guild.id].discard(user.id)
    await interaction.response.send_message(f"{user.mention} von der Whitelist entfernt.")

@bot.tree.command(name="blacklist_add", description="Fügt einen User zur Blacklist hinzu")
async def blacklist_add(interaction: discord.Interaction, user: discord.Member):
    if interaction.user.id != BOT_ADMIN_ID:
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    blacklists[interaction.guild.id].add(user.id)
    await interaction.response.send_message(f"{user.mention} zur Blacklist hinzugefügt.")

@bot.tree.command(name="blacklist_remove", description="Entfernt einen User von der Blacklist")
async def blacklist_remove(interaction: discord.Interaction, user: discord.Member):
    if interaction.user.id != BOT_ADMIN_ID:
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    blacklists[interaction.guild.id].discard(user.id)
    await interaction.response.send_message(f"{user.mention} von der Blacklist entfernt.")

@bot.tree.command(name="kick", description="Kickt einen User vom Server")
async def kick_cmd(interaction: discord.Interaction, user: discord.Member, reason: str = "Keine Angabe"):
    if not is_bot_admin(interaction):
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    await kick_member(interaction.guild, user, reason)
    await interaction.response.send_message(f"{user.mention} wurde gekickt. Grund: {reason}")

@bot.tree.command(name="ban", description="Bannt einen User vom Server")
async def ban_cmd(interaction: discord.Interaction, user: discord.Member, reason: str = "Keine Angabe"):
    if not is_bot_admin(interaction):
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    await ban_member(interaction.guild, user, reason)
    await interaction.response.send_message(f"{user.mention} wurde gebannt. Grund: {reason}")

@bot.tree.command(name="timeout", description="Timeout für einen User setzen")
async def timeout_cmd(interaction: discord.Interaction, user: discord.Member, stunden: int):
    if not is_bot_admin(interaction):
        await interaction.response.send_message("Keine Berechtigung.", ephemeral=True)
        return
    await timeout_member(user, stunden, f"Timeout durch {interaction.user}")
    await interaction.response.send_message(f"{user.mention} wurde für {stunden} Stunden getimeoutet.")

# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)
