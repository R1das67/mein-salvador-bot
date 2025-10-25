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

ban_kick_actions: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=10))
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

def is_blacklisted(member: discord.Member | discord.User) -> bool:
    gid = getattr(getattr(member, "guild", None), "id", None)
    if gid is None:
        return False
    return member.id in blacklists[gid]

def is_bot_admin(ctx: commands.Context) -> bool:
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


# ---------- Nachricht an Eigentümer nach Neustart ----------
async def notify_owner_after_restart():
    await asyncio.sleep(3)  # kurz warten bis Bot vollständig bereit ist
    message_text = (
        "**__🌐 Globex Security 🌐__**\n"
        "**@User**, lieber Eigentümer des Servers **(servername)**,\n"
        "aufgrund dessen, dass mein Besitzer regelmäßig einen neuen Free-Plan bei einem Hosting-Anbieter beantragen muss, "
        "wurde ich neu gestartet.\n"
        "Dabei werden leider alle Einträge der Whitelist und Blacklist zurückgesetzt.\n"
        "Daher möchten wir Sie bitten, Ihre Whitelist und Blacklist erneut einzurichten.\n\n"
        "**Mit freundlichen Grüßen,**\n"
        "**__Globex Security__**"
    )

    for guild in bot.guilds:
        try:
            owner = guild.owner or await bot.fetch_user(guild.owner_id)
            if owner:
                try:
                    await owner.send(message_text.replace("@User", owner.mention).replace("(servername)", guild.name))
                    log(f"Neustart-Nachricht an {owner} per DM gesendet ({guild.name})")
                except (Forbidden, HTTPException):
                    channel = discord.utils.get(guild.text_channels, name="moderator-only")
                    if channel:
                        await channel.send(message_text.replace("@User", owner.mention).replace("(servername)", guild.name))
                        log(f"Neustart-Nachricht an #{channel.name} in {guild.name} gesendet")
                    else:
                        log(f"Kein 'moderator-only'-Kanal in {guild.name} gefunden.")
        except Exception as e:
            log(f"Fehler beim Benachrichtigen des Eigentümers in {guild.name}: {e}")


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

    # Nachricht an Eigentümer nach Neustart
    asyncio.create_task(notify_owner_after_restart())

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

# ---------- Start ----------
if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Fehlende Umgebungsvariable DISCORD_TOKEN.")
    bot.run(TOKEN)
