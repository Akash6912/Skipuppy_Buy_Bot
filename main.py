import random
import time
import aiohttp
import asyncio
import json
import logging
import os
import qrcode
import requests
import sqlite3
import warnings
import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from eth_account import Account
from telegram import Update, InputFile, ReplyKeyboardRemove, InlineKeyboardMarkup, \
    InlineKeyboardButton, BotCommand
from telegram.ext import Application, ConversationHandler, CommandHandler, MessageHandler, CallbackQueryHandler, \
    filters, ContextTypes
from telegram.warnings import PTBUserWarning
from web3 import Web3

from swapcode import Uniswap

# Suppress only PTBUserWarning (not all warnings)
warnings.filterwarnings("ignore", category=PTBUserWarning)

load_dotenv(override=True)

# ================= GLOBAL VARIABLES ================= #
TOKEN_CONTRACT = "0x2fF5bE03a5456aB99836cc2caA4Ae0d158680581"  # required token
MIN_BALANCE = 100  # minimum amount of token needed to use txnbot (adjust as needed)
WETH_ADDRESS = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
ROUTER_ADDRESS = Web3.to_checksum_address("0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24")
ROUTER_ABI = json.loads("""
[
  {
    "inputs": [
      {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
      {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
      {"internalType": "address[]", "name": "path", "type": "address[]"},
      {"internalType": "address", "name": "to", "type": "address"},
      {"internalType": "uint256", "name": "deadline", "type": "uint256"}
    ],
    "name": "swapExactTokensForETH",
    "outputs": [
      {"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
      {"internalType": "address[]", "name": "path", "type": "address[]"},
      {"internalType": "address", "name": "to", "type": "address"},
      {"internalType": "uint256", "name": "deadline", "type": "uint256"}
    ],
    "name": "swapExactETHForTokens",
    "outputs": [
      {"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}
    ],
    "stateMutability": "payable",
    "type": "function"
  }
]
""")

ERC20_ABI = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}],
     "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"}
]
WETH_ABI = [
    {"constant": False, "inputs": [], "name": "deposit", "outputs": [], "payable": True, "stateMutability": "payable",
     "type": "function"},
    {"constant": False, "inputs": [{"name": "wad", "type": "uint256"}], "name": "withdraw", "outputs": [],
     "payable": False, "stateMutability": "nonpayable", "type": "function"},
]
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
ERROR_LOG_FILE = "swap_errors.txt"
FERNET_KEY = os.environ.get("MASTER_KEY")
BATCH_SIZE = 5
MAX_RETRIES = 5

# ================= STORE VARIABLES ================= #
user_swap_state = {}
user_locks = {}
pending_remove = {}  # uid -> True
user_rpc_map = {}  # sticky RPC assignment per user
next_rpc_index = 0  # round-robin pointer

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
# --- Web3 Setup (Base Chain) ---
# List of available Base RPC endpoints
RPC_ENDPOINTS = [
    os.environ.get("BASE_RPC"),
    os.environ.get("BASE_RPC1")
]

# Keep web3 instances per endpoint
W3_POOL = [Web3(Web3.HTTPProvider(rpc)) for rpc in RPC_ENDPOINTS]

# Reuse a thread pool for blocking web3 calls
executor = ThreadPoolExecutor(max_workers=30)


def get_user_w3(uid: int) -> Web3:
    """
    Assign an RPC provider to the user based on uid.
    If more users than RPCs, reuse them round-robin.
    """
    index = uid % len(W3_POOL)
    return W3_POOL[index]


# --- DB setup ---
def init_db():
    conn = sqlite3.connect("wallets.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            telegram_id INTEGER PRIMARY KEY,
            address TEXT,
            encrypted_privkey TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_wallet_row(telegram_id):
    conn = sqlite3.connect("wallets.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM wallets WHERE telegram_id=?", (telegram_id,))
    row = cur.fetchone()
    conn.close()
    return row


def store_wallet(telegram_id, address, encrypted_privkey):
    conn = sqlite3.connect("wallets.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO wallets (telegram_id, address, encrypted_privkey) VALUES (?,?,?)",
        (telegram_id, address, encrypted_privkey),
    )
    conn.commit()
    conn.close()


# --- Wallet generator ---
Account.enable_unaudited_hdwallet_features()


def create_new_eth_wallet():
    acct, mnemonic = Account.create_with_mnemonic()
    privkey_hex = acct.key.hex()
    return privkey_hex, acct.address


# --- Encryption helpers ---
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    print("⚠️ WARNING: Generated new FERNET_KEY. Save this in your .env to keep wallets consistent:", FERNET_KEY)

fernet = Fernet(FERNET_KEY.encode())


def encrypt_privkey(privkey_hex: str) -> str:
    return fernet.encrypt(privkey_hex.encode()).decode()


def decrypt_privkey(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()


# ================= Start Handler ================= #
async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # 1. Check if wallet exists
    row = get_wallet_row(user_id)

    if row:
        # Existing user
        address = row[1]
    else:
        # 2. Create new wallet
        privkey_hex, address = create_new_eth_wallet()
        encrypted = encrypt_privkey(privkey_hex)

        # 3. Store in DB
        store_wallet(user_id, address, encrypted)

    keyboard = [
        [InlineKeyboardButton("💼 My Wallet", callback_data="mywallet")],
        [InlineKeyboardButton("🔑 Export Key", callback_data="exportkey")],
        [InlineKeyboardButton("💰 Balance", callback_data="balance")],
        [InlineKeyboardButton("📥 Deposit", callback_data="deposit"),
         InlineKeyboardButton("📤 Withdraw", callback_data="withdraw")],
        [InlineKeyboardButton("🛒 Buy", callback_data="buy"),
         InlineKeyboardButton("📉 Sell", callback_data="sell")],
        [InlineKeyboardButton("🤖 TxnBot (Multi-Buy)", callback_data="txnbot")],
        [InlineKeyboardButton("❓ Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "👋 Welcome to your Trading Bot!\n\n"
        f"💼 Your wallet address:\n <code>{address}</code>\n"
        "\nChoose an option below:",
        reply_markup=reply_markup,
        parse_mode="HTML",
    )


# ================= Wallet Handler ================= #
async def mywallet_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)
    if not row:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text="No wallet found. Use /start to create one.")
        return

    address = row[1]
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=f"💼 Your wallet address:\n <code>{address}</code>\n",
        parse_mode="HTML",
    )
    await asyncio.sleep(2)
    await show_main_menu(update, context, edit=True)


# ================= ExportKey Handler ================= #
async def exportkey_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)
    if not row:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text="No wallet found. Use /start to create one.")
        return

    try:
        privkey_hex = decrypt_privkey(row[2])
    except Exception:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Error decrypting your private key.")
        return

    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=(
            "🔐 PRIVATE KEY (keep this secret)\n\n"
            f"<code>{privkey_hex}</code>\n\n"
            "⚠️ Anyone with this key controls your funds. Do NOT share\n"
            "Import into Coinbase Wallet → then delete this message."
        ),
        parse_mode="HTML",
    )
    await asyncio.sleep(2)
    await show_main_menu(update, context, edit=True)


# ================= Balance Handler ================= #
async def fetch_metadata(session, contract_address):
    """Fetch token metadata from Alchemy for a given contract."""
    meta_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getTokenMetadata",
        "params": [contract_address]
    }
    async with session.post(os.environ.get("BASE_RPC"), json=meta_payload) as resp:
        try:
            data = await resp.json()
            return contract_address, data.get("result", {})
        except Exception:
            return contract_address, {}


async def balance_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)
    w3 = get_user_w3(tid)
    if not row:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text="⚠️ No wallet found. Use /start to create one.")
        return

    address = row[1]

    # Step 1: Fetch balances
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getTokenBalances",
        "params": [address]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(os.environ.get("BASE_RPC"), json=payload) as resp:
            try:
                data = await resp.json()
            except Exception:
                await context.bot.send_message(chat_id=update.effective_chat.id,
                                               text="⚠️ Error: Could not decode JSON.")
                return

        if "result" not in data or "tokenBalances" not in data["result"]:
            print("❌ Invalid response structure:", data)
            await context.bot.send_message(chat_id=update.effective_chat.id,
                                           text="⚠️ Error: Invalid response from Alchemy.")
            return

        balances = data["result"]["tokenBalances"]

        # Collect non-zero tokens
        nonzero_tokens = []
        for token in balances:
            raw_balance = int(token["tokenBalance"], 16)  # hex → int
            if raw_balance > 0:
                nonzero_tokens.append((token["contractAddress"], raw_balance))

        # Step 2: Fetch metadata in parallel
        tasks = [fetch_metadata(session, contract) for contract, _ in nonzero_tokens]
        metadata_results = await asyncio.gather(*tasks)

    # Map contract → metadata
    metadata_map = {contract: meta for contract, meta in metadata_results}

    # Step 3: Build message
    msg = f"💰 <b>Wallet Balances (Base)</b>\n<code>{address}</code>\n\n"

    if not nonzero_tokens:
        msg += "No tokens found.\n"
    else:
        msg += f"• ETH (Ethereum): {w3.from_wei(w3.eth.get_balance(row[1]), 'ether') :.6f}\n"
        for contract, raw_balance in nonzero_tokens:
            meta = metadata_map.get(contract, {})
            decimals = meta.get("decimals", 18)
            symbol = meta.get("symbol", "???")
            name = meta.get("name", "")

            human = raw_balance / (10 ** decimals)
            msg += f"• {symbol} ({name}): {human:.6f}\n"

    await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")
    await asyncio.sleep(2)
    await show_main_menu(update, context, edit=True)


# ================= Help Handler ================= #
async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=(
            "/start: Start the bot & show menu\n"
            "/mywallet: Show your wallet address\n"
            "/exportkey: Export private key\n"
            "/balance: Check wallet balance\n"
            "/deposit: Deposit funds\n"
            "/withdraw: Withdraw funds\n"
            "/buy: Swap ETH → Token\n"
            "/sell: Swap Token → ETH\n"
            "/txnbot: Multi-buy transaction bot\n"
            "/cancel: Cancel the ongoing txnbot swaps\n"
            "/remove: To remove the wallet created from database\n"
            "/help: Help & usage guide\n\n"
            "Security reminder: do not share your private key with strangers. Keep the MASTER_KEY safe on the server."
        ),
    )
    await asyncio.sleep(2)
    await show_main_menu(update, context, edit=True)


# ================= Deposit Handlers ================= #
async def deposit_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)
    if not row:
        await context.bot.send_message(chat_id=update.effective_chat.id,
                                       text="⚠️ No wallet found. Use /start to create one.")
        return

    address = row[1]

    msg = (
        "💸 <b>Deposit Funds</b>\n\n"
        f"Send ETH or ERC-20 tokens on <b>Base chain</b> to this address:\n"
        f"<code>{address}</code>\n\n"
        "⚠️ Only send assets on Base chain (Chain ID: 8453). Sending from another chain may result in loss of funds."
    )

    # Generate QR Code for address
    qr = qrcode.make(address)
    bio = BytesIO()
    qr.save(bio, format="PNG")
    bio.seek(0)

    await context.bot.send_photo(
        chat_id=update.effective_chat.id,
        photo=InputFile(bio, filename="deposit_qr.png"),
        caption=msg,
        parse_mode="HTML"
    )
    await asyncio.sleep(2)
    await show_main_menu(update, context, edit=True)


# ================= Withdrawal Handlers ================= #
WITHDRAW_ADDRESS, WITHDRAW_AMOUNT = range(2)


# Step 0: Start withdraw (button or command)
async def withdraw_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message:  # /withdraw command
        await update.message.reply_text("📨 Enter the recipient wallet address:")
    elif update.callback_query:  # Button pressed
        query = update.callback_query
        await query.answer()
        await query.edit_message_text("📨 Enter the recipient wallet address:")
        # use edit_message_text instead of reply_text for callback_query

    return WITHDRAW_ADDRESS


# Step 1: Save and validate ETH address
async def withdraw_address(update: Update, context: ContextTypes.DEFAULT_TYPE):
    address = update.message.text.strip()
    try:
        address = Web3.to_checksum_address(address)
    except Exception:
        await update.message.reply_text("❌ Invalid address. Please enter a valid Base/Ethereum address:")
        return WITHDRAW_ADDRESS

    context.user_data["address"] = address
    await update.message.reply_text("✅ Address saved. Now enter the ETH amount to withdraw:")
    return WITHDRAW_AMOUNT


# Step 2: Save amount & execute withdrawal
async def withdraw_amount(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)  # (tid, wallet_address, encrypted_privkey)
    BOT_ADDRESS = row[1]
    w3 = get_user_w3(tid)

    try:
        amount = float(update.message.text.strip())
    except ValueError:
        await update.message.reply_text("❌ Invalid number. Please enter a valid amount:")
        return WITHDRAW_AMOUNT

    recipient = context.user_data["address"]

    def send_withdrawal():
        """Run blocking web3 code in threadpool."""
        value = w3.to_wei(amount, "ether")
        nonce = w3.eth.get_transaction_count(BOT_ADDRESS)

        tx = {
            "to": recipient,
            "value": value,
            "gas": 21000,
            "gasPrice": w3.eth.gas_price,
            "nonce": nonce,
            "chainId": 8453  # Base mainnet
        }

        signed_tx = w3.eth.account.sign_transaction(tx, decrypt_privkey(row[2]))
        tx_final = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        return tx_final

    try:
        loop = asyncio.get_running_loop()
        tx_hash = await loop.run_in_executor(executor, send_withdrawal)

        txn_link = f"https://basescan.org/tx/{w3.to_hex(tx_hash)}"
        await update.message.reply_text(f"✅ ETH withdrawal sent!\n🔗 {txn_link}")

    except Exception as e:
        err_msg = extract_error_message(e)
        await update.message.reply_text(f"⚠️ Error while sending: {err_msg}")

    await asyncio.sleep(3)  # ✅ non-blocking sleep
    await show_main_menu(update, context, edit=True)
    return ConversationHandler.END


async def withdraw_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Withdrawal cancelled.", reply_markup=ReplyKeyboardRemove())
    await asyncio.sleep(3)  # ✅ non-blocking
    await show_main_menu(update, context, edit=True)
    return ConversationHandler.END


# --- ConversationHandler setup ---
withdraw_handler = ConversationHandler(
    entry_points=[
        CommandHandler("withdraw", withdraw_start),
        CallbackQueryHandler(withdraw_start, pattern="^withdraw$"),  # button
    ],
    states={
        WITHDRAW_ADDRESS: [MessageHandler(filters.TEXT & ~filters.COMMAND, withdraw_address)],
        WITHDRAW_AMOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, withdraw_amount)],
    },
    fallbacks=[CommandHandler("cancel", withdraw_cancel)],
    per_user=True,
    per_chat=True
)


# ================= Wrap/Unwrap eth Handlers ================= #
def wrap_eth_to_weth(private_key, amount_eth, w3: Web3) -> str:
    """Wrap ETH into WETH safely (with pending nonce + gas bump)."""
    try:
        account = Account.from_key(private_key)
        address = account.address

        weth = w3.eth.contract(address=WETH_ADDRESS, abi=WETH_ABI)

        # Always fetch latest pending nonce
        nonce = w3.eth.get_transaction_count(address, "pending")

        # Gas bump (10%)
        gas_price = int(w3.eth.gas_price * 1.1)

        tx = weth.functions.deposit().build_transaction({
            "from": address,
            "nonce": nonce,
            "value": w3.to_wei(amount_eth, "ether"),
            "gas": 100000,
            "gasPrice": gas_price,
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        return tx_hash.hex()

    except Exception as e:
        print(f"[ERROR] WETH wrap failed: {e}")
        raise


# --- Buy Handlers ---
async def buy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("Enter token address:")
    user_swap_state[update.effective_user.id] = {"step": "token_out", "mode": "buy"}


async def swap_handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    state = user_swap_state.get(uid)

    if not state:
        await update.message.reply_text("⚠️ No active swap session. Start again with /buy or /txnbot.")
        return

    # --- BUY flow ---
    if state.get("mode") == "buy":
        if state["step"] == "token_out":
            token_out = update.message.text.strip()
            state["token_out"] = token_out
            state["step"] = "amount"
            await update.message.reply_text(
                f"Enter amount of ETH to swap for {token_out}:"
            )

        elif state["step"] == "amount":
            try:
                amount = float(update.message.text.strip())
                state["amount"] = amount

                # ✅ Ask pool selection (instead of confirm directly)
                keyboard = [[
                    InlineKeyboardButton("Uniswap V2", callback_data="pool_v2"),
                    InlineKeyboardButton("Uniswap V3", callback_data="pool_v3")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Choose pool version for swapping {amount} ETH → {state['token_out']}:",
                    reply_markup=reply_markup
                )
                state["step"] = "pool"

            except ValueError:
                await update.message.reply_text("⚠️ Invalid ETH amount. Enter a number.")

    # -------- SELL FLOW --------
    elif state.get("mode") == "sell":
        if state["step"] == "token_in":
            state["token_in"] = update.message.text.strip()
            state["step"] = "amount"
            await update.message.reply_text("Enter token amount to sell:")

        elif state["step"] == "amount":
            try:
                state["amount"] = float(update.message.text.strip())
                state["step"] = "pool_version"

                keyboard = [
                    [InlineKeyboardButton("V2", callback_data="sell_pool_v2"),
                     InlineKeyboardButton("V3", callback_data="sell_pool_v3")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Select pool version for selling {state['amount']} of {state['token_in']}:",
                    reply_markup=reply_markup
                )
            except ValueError:
                await update.message.reply_text("⚠️ Invalid token amount. Enter a number.")

    # --- TXNBOT flow ---
    elif state.get("mode") == "txnbot":
        if state["step"] == "token_out":
            token_out = update.message.text.strip()
            state["token_out"] = token_out
            state["step"] = "amount"
            await update.message.reply_text(
                f"Enter amount of ETH per transaction to swap for {token_out}:"
            )

        elif state["step"] == "amount":
            try:
                amount = float(update.message.text.strip())
                state["amount"] = amount
                state["step"] = "count"
                await update.message.reply_text(
                    "How many transactions do you want to run?"
                )
            except ValueError:
                await update.message.reply_text("⚠️ Invalid ETH amount. Enter a number.")

        elif state["step"] == "count":
            try:
                count = int(update.message.text.strip())
                state["count"] = count

                # ✅ Ask pool selection
                keyboard = [[
                    InlineKeyboardButton("Uniswap V2", callback_data="pool_v2"),
                    InlineKeyboardButton("Uniswap V3", callback_data="pool_v3")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Choose pool version for {count} swaps of {state['amount']} ETH → {state['token_out']}:",
                    reply_markup=reply_markup
                )
                state["step"] = "pool"

            except ValueError:
                await update.message.reply_text("⚠️ Invalid count. Enter a number.")


def assign_rpc(uid: int) -> str:
    """
    Assign an RPC to a user in round-robin fashion.
    Each user sticks to the same RPC until restart.
    """
    global next_rpc_index
    if uid not in user_rpc_map:
        rpc_url = RPC_ENDPOINTS[next_rpc_index]
        user_rpc_map[uid] = rpc_url
        next_rpc_index = (next_rpc_index + 1) % len(RPC_ENDPOINTS)
    return user_rpc_map[uid]


# -------------------------------
# V2 Sync Buy
# -------------------------------
def do_buy_sync_v2(wallet, private_key, token_out, amount, rpc_url):
    """Perform Uniswap V2 ETH -> Token buy (Base chain) with debug logging."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    router = w3.eth.contract(address=ROUTER_ADDRESS, abi=ROUTER_ABI)

    TOKEN_OUT = Web3.to_checksum_address(token_out)

    # Deadline for txn validity
    deadline = w3.eth.get_block("latest")["timestamp"] + 60 * 5  # 5 min
    path = [WETH_ADDRESS, TOKEN_OUT]

    print("🔹 Starting Uniswap V2 swap...")
    print(f"   → Wallet: {wallet}")
    print(f"   → RPC URL: {rpc_url}")
    print(f"   → Swap amount (ETH): {amount}")
    print(f"   → Token Out: {TOKEN_OUT}")
    print(f"   → Path: {path}")
    print(f"   → Deadline (unix): {deadline}")

    # --- Estimate gas ---
    try:
        gas_estimate = router.functions.swapExactETHForTokens(
            0, path, wallet, deadline
        ).estimate_gas({
            "from": wallet,
            "value": w3.to_wei(amount, "ether"),
        })
        print(f"   ✅ Gas estimate: {gas_estimate} units")
    except Exception as e:
        print(f"   ❌ Gas estimation failed: {e}")
        raise

    # --- Fetch gas price ---
    gas_price = w3.eth.gas_price
    print(f"   → Current gas price: {gas_price} wei ({w3.from_wei(gas_price, 'gwei')} gwei)")

    # --- Get nonce ---
    nonce = w3.eth.get_transaction_count(wallet)
    print(f"   → Nonce: {nonce}")

    # --- Build transaction ---
    txn = router.functions.swapExactETHForTokens(
        0, path, wallet, deadline
    ).build_transaction({
        "from": wallet,
        "value": w3.to_wei(amount, "ether"),
        "gas": int(gas_estimate * 1.1),  # add 10% buffer
        "gasPrice": gas_price,
        "nonce": nonce,
        "chainId": 8453,  # Base mainnet
    })

    print("   ✅ Transaction built:")
    print(f"      - Value (ETH): {amount}")
    print(f"      - Gas (with buffer): {txn['gas']}")
    print(f"      - Gas Price: {txn['gasPrice']} wei")
    print(f"      - Nonce: {txn['nonce']}")
    print(f"      - ChainID: {txn['chainId']}")

    # --- Sign transaction ---
    signed_txn = w3.eth.account.sign_transaction(txn, private_key=private_key)
    print(f"   🔑 Transaction signed (hash preview): {signed_txn.hash.hex()}")

    # --- Send transaction ---
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    print(f"   🚀 Transaction broadcasted! Tx Hash: {tx_hash.hex()}")

    return tx_hash.hex()


# -------------------------------
# V3 Sync Buy
# -------------------------------
def do_buy_sync_v3(wallet, private_key, token_out, amount, rpc_url):
    """Perform Uniswap V3 ETH -> Token buy (Base chain)."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    uniswap = Uniswap(
        wallet_address=wallet,
        private_key=private_key,
        provider=rpc_url,
        web3=w3
    )

    value = w3.to_wei(amount, "ether")

    tx_hash = uniswap.make_trade(
        from_token=WETH_ADDRESS,
        to_token=token_out,
        amount=value,
        fee=10000,
        slippage=2,
        pool_version="v3"
    )
    return tx_hash.hex()


# -------------------------------
# Unified Async Wrapper
# -------------------------------
async def perform_buy(uid, wallet, private_key, token_out, amount, pool_version="v3", max_retries=MAX_RETRIES):
    """
    Unified buy function: supports Uniswap V2 and V3.
    - V2 swaps unchanged
    - V3 optimized: wraps ETH->WETH, fast retries, executor-friendly
    """
    loop = asyncio.get_running_loop()
    delay = 0.5 if pool_version.lower() == "v3" else 5

    base_rpc = assign_rpc(uid)
    base_index = RPC_ENDPOINTS.index(base_rpc)

    for attempt in range(1, max_retries + 1):
        rpc_url = RPC_ENDPOINTS[(base_index + attempt - 1) % len(RPC_ENDPOINTS)]
        try:
            if pool_version.lower() == "v2":
                tx_hash = await asyncio.wait_for(
                    loop.run_in_executor(
                        executor,
                        do_buy_sync_v2,
                        wallet, private_key, token_out, amount, rpc_url
                    ),
                    timeout=30
                )

            else:  # V3
                # Wrap ETH -> WETH for V3
                await loop.run_in_executor(None, wrap_eth_to_weth, private_key, amount,
                                           Web3(Web3.HTTPProvider(rpc_url)))

                # Perform the V3 swap
                tx_hash = await asyncio.wait_for(
                    loop.run_in_executor(
                        executor,
                        do_buy_sync_v3,
                        wallet, private_key, token_out, amount, rpc_url
                    ),
                    timeout=30
                )

            if not tx_hash:
                raise Exception("No tx hash returned")

            print(f"[SUCCESS] Swap submitted for wallet {wallet}: {tx_hash}")
            return tx_hash

        except asyncio.TimeoutError:
            if attempt == max_retries:
                raise Exception(f"Swap timed out after {max_retries} attempts (last RPC={rpc_url})")
            print(f"[WARN] Swap timed out (attempt {attempt}, RPC={rpc_url}), retrying in {delay}s...")

        except Exception as e:
            if attempt == max_retries:
                raise
            print(f"[WARN] Swap failed (attempt {attempt}, RPC={rpc_url}): {e}. Retrying in {delay}s...")

        await asyncio.sleep(delay + random.uniform(0, 1))
        delay = min(delay * 2, 2 if pool_version.lower() == "v3" else 60)


async def with_user_lock(uid, coro):
    """Ensure one user's swaps run sequentially, but allow concurrency across users."""
    if uid not in user_locks:
        user_locks[uid] = asyncio.Lock()
    async with user_locks[uid]:
        return await coro


# ================= Sell Handler ================= #
def get_eth_balance(address, w3):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # WETH address on Base
    WETH_ADDRESS = "0x4200000000000000000000000000000000000006".lower()

    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "alchemy_getTokenBalances",
        "params": [address, "erc20"]
    }

    response = requests.post(os.environ.get("BASE_RPC"), headers=headers, data=json.dumps(payload))

    if response.status_code == 200:
        data = response.json()

        balances = data.get("result", {}).get("tokenBalances", [])
        weth_balance_hex = None

        for token in balances:
            contract_address = token["contractAddress"].lower()
            if contract_address == WETH_ADDRESS:
                weth_balance_hex = token["tokenBalance"]
                break

        if weth_balance_hex:
            weth_balance = int(weth_balance_hex, 16) / (10 ** 18)  # WETH uses 18 decimals
            return weth_balance
        else:
            print("No WETH balance found.")
            return 0
    else:
        print("Error:", response.status_code, response.text)


# --- SELL COMMAND ---
async def sell_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("Enter token address you want to sell:")
    user_swap_state[update.effective_user.id] = {"step": "token_in", "mode": "sell"}


# --- Sync Sell with specific RPC ---
async def perform_sell_v2_v3(wallet, private_key, token_in, amount, pool_version, slippage=0.05, max_retries=10):
    """
    Perform a sell transaction (token -> WETH -> ETH) on either V2 or V3 pool.
    Retries until successful or balance < amount.
    """
    loop = asyncio.get_running_loop()

    def sync_sell():
        w3 = Web3(Web3.HTTPProvider(assign_rpc(wallet)))
        print(f"[DEBUG] Using RPC: {w3.provider.endpoint_uri}")

        # --- Minimal ERC20 ABI for balance/decimals/approve ---
        ERC20_ABI = json.loads("""
        [
            {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
            {"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},
            {"constant":false,"inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"type":"function"}
        ]
        """)
        token_contract = w3.eth.contract(address=w3.to_checksum_address(token_in), abi=ERC20_ABI)

        decimals = token_contract.functions.decimals().call()
        balance = token_contract.functions.balanceOf(wallet).call()
        value_wei = int(amount * (10 ** decimals))

        print(f"[DEBUG] Token decimals: {decimals}")
        print(f"[DEBUG] Wallet balance: {balance / (10 ** decimals)}")
        print(f"[DEBUG] Sell amount: {amount}")

        if balance < value_wei:
            raise ValueError("❌ Not enough token balance")

        tx_hash = None

        if pool_version == "v3":
            print("[DEBUG] Using Uniswap V3 pool")
            uniswap = Uniswap(
                wallet_address=wallet,
                private_key=private_key,
                provider=w3.provider.endpoint_uri,
                web3=w3
            )
            tx_hash = uniswap.make_trade(
                from_token=token_in,
                to_token="0x4200000000000000000000000000000000000006",  # WETH
                amount=value_wei,
                fee=10000,
                slippage=int(slippage * 100),
                pool_version="v3"
            )

        elif pool_version == "v2":
            print("[DEBUG] Using Uniswap V2 pool")
            router = w3.eth.contract(address=ROUTER_ADDRESS, abi=ROUTER_ABI)
            TOKEN_IN = w3.to_checksum_address(token_in)
            WETH = w3.to_checksum_address("0x4200000000000000000000000000000000000006")
            path = [TOKEN_IN, WETH]

            # --- Approve router ---
            print("[DEBUG] Approving token for router...")
            approve_txn = token_contract.functions.approve(
                ROUTER_ADDRESS,
                value_wei
            ).build_transaction({
                "from": wallet,
                "nonce": w3.eth.get_transaction_count(wallet),
                "gas": 100000,
                "gasPrice": w3.eth.gas_price
            })
            signed_approve = w3.eth.account.sign_transaction(approve_txn, private_key=private_key)
            approve_hash = w3.eth.send_raw_transaction(signed_approve.raw_transaction)
            w3.eth.wait_for_transaction_receipt(approve_hash)
            print(f"[DEBUG] Approved token: {approve_hash.hex()}")

            # --- Swap ---
            print("[DEBUG] Performing swapExactTokensForETH...")
            deadline = w3.eth.get_block("latest")["timestamp"] + 60 * 5
            gas_estimate = router.functions.swapExactTokensForETH(
                value_wei, 0, path, wallet, deadline
            ).estimate_gas({"from": wallet})
            gas_price = w3.eth.gas_price

            txn = router.functions.swapExactTokensForETH(
                value_wei, 0, path, wallet, deadline
            ).build_transaction({
                "from": wallet,
                "gas": int(gas_estimate * 1.1),
                "gasPrice": gas_price,
                "nonce": w3.eth.get_transaction_count(wallet),
                "chainId": 8453
            })

            signed_txn = w3.eth.account.sign_transaction(txn, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            print(f"[DEBUG] Swap submitted: {tx_hash.hex()}")

        else:
            raise Exception(f"Unknown pool_version: {pool_version}")

        return f"✅ Sell successful!\n🔗 https://basescan.org/tx/0x{tx_hash.hex()}"

    # --- Retry logic ---
    delay = 5
    for attempt in range(1, max_retries + 1):
        try:
            result = await loop.run_in_executor(executor, sync_sell)
            return result  # ✅ success
        except ValueError as e:
            # balance too low → stop
            return str(e)
        except Exception as e:
            print(f"[WARN] Sell attempt {attempt} failed: {e}. Retrying in {delay}s...")
            await asyncio.sleep(delay + random.uniform(0, 2))
            delay = min(delay * 2, 60)

    return f"⚠️ Sell failed after {max_retries} retries"


async def sell_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    if uid not in user_swap_state:
        await query.edit_message_text("⚠️ Session expired. Start again with /sell.")
        return

    state = user_swap_state[uid]

    # -------- CANCEL --------
    if query.data.startswith("cancel_sell"):
        await query.edit_message_text("❌ Sell cancelled.")
        user_swap_state.pop(uid, None)
        return

    # -------- SELECT POOL --------
    elif query.data in ["sell_pool_v2", "sell_pool_v3"]:
        state["pool_version"] = query.data.split("_")[-1]
        state["step"] = "confirm"

        keyboard = [[
            InlineKeyboardButton("✅ Confirm", callback_data="confirm_sell"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_sell")
        ]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"Sell {state['amount']} of {state['token_in']} using {state['pool_version']} pool?\nConfirm to proceed.",
            reply_markup=reply_markup
        )

    # -------- CONFIRM SELL --------
    elif query.data == "confirm_sell":
        wallet_data = get_wallet_row(uid)
        wallet = wallet_data[1]
        private_key = decrypt_privkey(wallet_data[2])
        token_in = state["token_in"]
        amount = state["amount"]
        pool_version = state["pool_version"]

        await query.edit_message_text(f"⏳ Selling {amount} of {token_in} using {pool_version} pool...")

        async def task():
            try:
                result_msg = await perform_sell_v2_v3(wallet, private_key, token_in, amount, pool_version)
                await context.bot.send_message(chat_id=query.message.chat_id, text=result_msg)
            finally:
                user_swap_state.pop(uid, None)
                await show_main_menu(update, context, edit=True)

        asyncio.create_task(task())


# ================= TXNBOT MULTIPLE SWAPS ================= #
async def txnbot_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    row = get_wallet_row(uid)
    if not row:
        await update.effective_message.reply_text("⚠️ Wallet not found. Please create/import a wallet first.")
        return

    wallet_address = row[1]
    w3 = get_user_w3(uid)

    try:
        token_contract = w3.eth.contract(address=w3.to_checksum_address(TOKEN_CONTRACT), abi=ERC20_ABI)
        balance = token_contract.functions.balanceOf(wallet_address).call()
        decimals = token_contract.functions.decimals().call()
        token_balance = balance / (10 ** decimals)

        if token_balance < MIN_BALANCE:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"⚠️ You need at least <b>{MIN_BALANCE}</b> tokens of \n <b>Skipuppy</b>: <code>{TOKEN_CONTRACT}</code> \nto use /txnbot.\n"
                     f"Your current balance: {token_balance:.6f}\n"
                     f"Please deposit or buy the required tokens first.",
                parse_mode="HTML"
            )
            return

    except Exception as e:
        await update.effective_message.reply_text(f"⚠️ Failed to check token balance: {str(e)}")
        return

    # If balance is sufficient, continue with txnbot flow
    await update.effective_message.reply_text("Enter token address for multiple swaps:")
    user_swap_state[uid] = {"step": "token_out", "mode": "txnbot"}


# --- BUTTON HANDLER (Single Buy / Multiple Buy) --- #
async def buy_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    row = get_wallet_row(uid)

    state = user_swap_state.get(uid)
    if not state:
        await query.edit_message_text("⚠️ Session expired. Start again with /buy or /txnbot.")
        return

    # --- Cancel flow ---
    if query.data.startswith("cancel_") or query.data == "cancel_swap":
        await query.edit_message_text("❌ Cancelled.")
        # Just mark cancel flag, don't pop here
        if uid in user_swap_state:
            user_swap_state[uid]["cancel"] = True
            if "task" in user_swap_state[uid]:
                task = user_swap_state[uid]["task"]
                if not task.done():
                    task.cancel()
        return

    # --- Pool selection ---
    if query.data in ["pool_v2", "pool_v3"]:
        pool = query.data.replace("pool_", "")  # "v2" or "v3"
        state["pool_version"] = pool

        keyboard = [[
            InlineKeyboardButton("✅ Confirm", callback_data="confirm_swap"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_swap")
        ]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        # Confirmation message
        if state["mode"] == "buy":
            await query.edit_message_text(
                f"🔎 Review Swap:\n\n"
                f"Swap {state['amount']} ETH → {state['token_out']}\n"
                f"Pool: {pool.upper()}\n\n"
                f"Proceed?",
                reply_markup=reply_markup
            )
        elif state["mode"] == "txnbot":
            await query.edit_message_text(
                f"🔎 Review Batch Swaps:\n\n"
                f"{state['count']} swaps of {state['amount']} ETH → {state['token_out']}\n"
                f"Pool: {pool.upper()}\n\n"
                f"Proceed?",
                reply_markup=reply_markup
            )
        return

    # --- Confirm swap ---
    if query.data == "confirm_swap":
        await query.edit_message_text("🚀 Executing swap...")

        wallet = row[1]
        private_key = decrypt_privkey(row[2])
        state["wallet"] = row[1]
        state["private_key"] = private_key
        token_out = state["token_out"]
        amount = state["amount"]
        pool = state.get("pool_version", "v3")

        try:
            if state["mode"] == "buy":
                tx_hash = await perform_buy(uid, wallet, private_key, token_out, amount, pool)
                await context.bot.send_message(
                    chat_id=uid,
                    text=f"✅ Swap submitted!\n🔗 https://basescan.org/tx/0x{tx_hash}"
                )

                # Cleanup immediately for one-off swap
                user_swap_state.pop(uid, None)

            elif state["mode"] == "txnbot":
                count = state["count"]
                task = asyncio.create_task(
                    run_swaps(uid, wallet, private_key, token_out, amount, count, 0, context, pool)
                )
                user_swap_state[uid]["task"] = task
                await context.bot.send_message(
                    chat_id=uid,
                    text=f"🚀 Running {count} swaps of {amount} ETH on {pool.upper()}..."
                )
                # ❌ do not pop here → let run_swaps or cancel handle cleanup

        except Exception as e:
            await context.bot.send_message(chat_id=uid, text=f"❌ Swap failed: {str(e)}")
            user_swap_state.pop(uid, None)
        return


# ------------------- SAVE & LOAD PROGRESS ------------------- #
def save_progress(uid, wallet, private_key, token_out, amount, count, current_index,
                  pool_version, temp_wallets, canceled=False):
    progress = {
        "uid": uid,
        "wallet": wallet,
        "private_key": private_key,
        "token_out": token_out,
        "amount": amount,
        "count": count,
        "current_index": current_index,
        "pool_version": pool_version,
        "canceled": canceled,
        "temp_wallets": temp_wallets
    }
    filename = f"progress_{uid}.json"
    try:
        with open(filename, "w") as f:
            json.dump(progress, f)
        print(f"[DEBUG] Progress saved | swap {current_index + 1}/{count}")
    except Exception as e:
        print(f"[ERROR] Failed to save progress for {uid}: {e}")


def load_progress(uid):
    try:
        with open(f"progress_{uid}.json", "r") as f:
            progress = json.load(f)
        if "pool_version" not in progress:
            progress["pool_version"] = "v3"
        if "temp_wallets" not in progress:
            progress["temp_wallets"] = []
        return progress
    except FileNotFoundError:
        return None


# ------------------- ETH HANDLER ------------------- #
def send_eth_from_master(w3, from_address, from_key, to_address, amount):
    """
    Send ETH synchronously. Raises exception if fails.
    """
    amount_wei = w3.to_wei(amount, "ether")
    nonce = w3.eth.get_transaction_count(from_address)
    tx = {
        "to": to_address,
        "value": int(amount_wei),
        "gas": 21000,
        "gasPrice": w3.eth.gas_price,
        "nonce": nonce,
        "chainId": 8453
    }
    signed_tx = w3.eth.account.sign_transaction(tx, from_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_hash


def sweep_leftover_eth(w3, temp_private_key, temp_address, master_wallet, max_retries=5, buffer_percent=0.02):
    """
    Sweep all leftover ETH from a temp wallet to a master wallet safely.
    Handles tiny balances, retries transient failures, uses EIP-1559 gas,
    and leaves a percentage buffer to prevent insufficient funds errors.
    """
    print(f"[INFO] Starting sweep from {temp_address} → {master_wallet}")
    gas_limit = 21000  # standard ETH transfer

    for attempt in range(1, max_retries + 1):
        try:
            # Use pending balance to include unconfirmed outgoing txs
            balance = w3.eth.get_balance(temp_address, block_identifier="pending")
            if balance <= 0:
                print(f"[INFO] Balance is zero, nothing to sweep.")
                return None

            max_priority_fee = w3.eth.max_priority_fee
            base_fee = w3.eth.get_block('pending').baseFeePerGas
            max_fee = int(base_fee * 1.2 + max_priority_fee)  # 20% buffer

            tx_cost = gas_limit * max_fee
            # Leave percentage buffer for safety
            buffer_wei = int(balance * buffer_percent)
            send_amount = balance - tx_cost - buffer_wei

            if send_amount <= 0:
                print(f"[INFO] Balance too low after gas and percentage buffer. Skipping sweep.")
                return None

            nonce = w3.eth.get_transaction_count(temp_address, "pending")

            tx = {
                "to": master_wallet,
                "value": int(send_amount),
                "gas": gas_limit,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": max_priority_fee,
                "nonce": nonce,
                "chainId": 8453
            }

            signed_tx = w3.eth.account.sign_transaction(tx, temp_private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            print(f"[SUCCESS] Swept {send_amount} wei to master wallet. TX: {w3.to_hex(tx_hash)}")
            return tx_hash

        except Exception as e:
            print(f"[WARN] Sweep attempt {attempt} failed: {e}")
            time.sleep(1)  # small delay before retry

    print(f"[ERROR] Failed to sweep leftover ETH from {temp_address} after {max_retries} attempts.")
    return None


async def fund_batch_wallets(w3, master_wallet, master_private_key, temp_address, amount_eth, max_retries=5):
    attempt = 0
    while attempt < max_retries:
        try:
            nonce = w3.eth.get_transaction_count(master_wallet, "pending")
            tx = {
                "from": master_wallet,
                "to": temp_address,
                "value": w3.to_wei(amount_eth, "ether"),
                "gas": 21000,
                "maxFeePerGas": w3.eth.gas_price,
                "maxPriorityFeePerGas": w3.eth.max_priority_fee,
                "nonce": nonce,
                "chainId": w3.eth.chain_id
            }
            signed_tx = w3.eth.account.sign_transaction(tx, master_private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

            if receipt.status == 1:
                print(f"[INFO] Funding successful for {temp_address} | nonce={nonce} | tx={tx_hash.hex()}")
                return tx_hash.hex()
            else:
                raise Exception("Funding tx failed on-chain")

        except Exception as e:
            attempt += 1
            err_msg = str(e).lower()
            print(f"[WARN] Funding attempt {attempt} for {temp_address} failed: {err_msg}")

            # if nonce issue, retry with fresh nonce
            if "nonce" in err_msg or "replacement transaction underpriced" in err_msg:
                await asyncio.sleep(1)  # small delay before retry
                continue
            else:
                await asyncio.sleep(2 ** attempt)  # exponential backoff

    raise Exception(f"Funding failed for {temp_address} after {max_retries} attempts")


# ------------------- RESUMABLE SWAP LOOP ------------------- #
async def run_swaps(uid, wallet, private_key, token_out, amount, count,
                    start_index=0, context=None, pool_version="v3", batch_size=BATCH_SIZE):
    w3 = get_user_w3(uid)
    msg = None

    # Load or initialize progress
    progress = load_progress(uid) or {"current_index": start_index - 1, "temp_wallets": []}
    success_count = progress["current_index"] + 1
    temp_wallets = progress["temp_wallets"]
    active_wallets = temp_wallets.copy()

    print(f"[INFO] Starting run_swaps for {uid}: total={count}, start_index={success_count}")

    i = success_count
    try:
        while i < count:
            batch_end = min(i + batch_size, count)
            current_batch_range = range(i, batch_end)

            # Prepare batch wallets
            batch_wallets = []
            for idx in current_batch_range:
                if idx < len(active_wallets):
                    wallet_info = active_wallets[idx]
                else:
                    temp_pk, temp_addr = create_new_eth_wallet()
                    temp_addr = Web3.to_checksum_address(temp_addr)
                    wallet_info = {"private_key": temp_pk, "address": temp_addr, "completed": False}
                    active_wallets.append(wallet_info)
                batch_wallets.append(wallet_info)

            # Fund wallets for gas if needed
            for wallet_info in batch_wallets:
                if not wallet_info.get("funded"):
                    await fund_batch_wallets(w3, wallet, private_key, wallet_info["address"], 0.00001)
                    wallet_info["funded"] = True

            # Launch swaps concurrently for V3
            swap_tasks = [
                perform_buy(uid, wallet_info["address"], wallet_info["private_key"],
                            token_out, amount, pool_version=pool_version)
                for wallet_info in batch_wallets if not wallet_info["completed"]
            ]

            # Process swaps as they complete (sequential Telegram notifications)
            for coro in asyncio.as_completed(swap_tasks):
                try:
                    tx_hash = await coro
                    # Identify wallet index
                    wallet_info = next(w for w in batch_wallets if not w["completed"])
                    wallet_info["completed"] = True
                    success_count += 1

                    save_progress(uid, wallet, private_key, token_out, amount, count,
                                  i, pool_version=pool_version, temp_wallets=active_wallets)

                    # Notify Telegram
                    if msg:
                        await safe_edit(uid, None, msg,
                                        f"✅ Swap {i + 1}/{count} [{pool_version.upper()}]")
                    else:
                        msg = await context.bot.send_message(
                            chat_id=uid,
                            text=f"✅ Swap {i + 1}/{count} [{pool_version.upper()}]"
                        )

                    i += 1

                except Exception as e:
                    print(f"[WARN] Swap failed: {e}. Will retry in next batch if needed.")

            # Sweep completed wallets
            print(f"[INFO] Sweeping completed wallets for batch {i // batch_size}")
            await sweep_completed_wallets(w3, active_wallets, wallet)

    except asyncio.CancelledError:
        print("[INFO] Cancel requested. Sweeping all completed wallets...")
        await sweep_all_wallets(w3, active_wallets, wallet)
        cleanup(uid, wallet, private_key, w3)
        return

    # Final cleanup
    await asyncio.sleep(1)
    print(f"[INFO] All swaps completed for {uid}. Sweeping remaining wallets...")
    await sweep_all_wallets(w3, active_wallets, wallet)
    cleanup(uid)

    if msg:
        await safe_edit(uid, None, msg,
                        f"🎉 Completed {success_count}/{count} swaps [{pool_version.upper()}]")

    user_swap_state.pop(uid, None)
    await asyncio.sleep(2)


async def sweep_completed_wallets(w3, wallets, master_wallet):
    for wallet_info in wallets:
        if wallet_info.get("completed"):
            try:
                bal = w3.eth.get_balance(wallet_info["address"])
                if w3.from_wei(bal, "ether") >= 0.000001:
                    print(f"[INFO] Sweeping {w3.from_wei(bal, 'ether'):.8f} ETH from {wallet_info['address']}")
                    sweep_leftover_eth(w3, wallet_info["private_key"], wallet_info["address"], master_wallet)
                else:
                    print(f"[INFO] Skipping sweep for {wallet_info['address']}: balance too low")
            except Exception as e:
                print(f"[WARN] Sweeping {wallet_info['address']} failed: {e}")


async def sweep_all_wallets(w3, temp_wallets, master_wallet):
    """
    Sweep leftover ETH from *all* temp wallets, regardless of completion status.
    Only sweeps if balance > 0.000001 ETH.
    """
    min_threshold = w3.to_wei("0.000001", "ether")

    for tw in temp_wallets:
        try:
            balance = w3.eth.get_balance(tw["address"])
            if balance > min_threshold:
                print(f"[SWEEP] Sweeping {w3.from_wei(balance, 'ether')} ETH from {tw['address']}...")
                sweep_leftover_eth(w3, tw["private_key"], tw["address"], master_wallet)
        except Exception as e:
            print(f"[WARN] Sweep failed for {tw['address']}: {e}")


def cleanup(uid):
    """Common cleanup routine for cancel/finish."""
    try:
        os.remove(f"progress_{uid}.json")
    except FileNotFoundError:
        pass
    user_swap_state.pop(uid, None)


# ------------------- AUTO-RESUME ON BOT START ------------------- #
async def auto_resume_all(bot):
    """
    Auto-resume swaps from progress files if not canceled.
    Supports completed-wallet tracking.
    """
    resumed_any = False

    for file in os.listdir("."):
        if file.startswith("progress_") and file.endswith(".json"):
            try:
                with open(file, "r") as f:
                    progress = json.load(f)

                # skip if canceled
                if progress.get("canceled"):
                    continue

                uid = progress["uid"]
                wallet = progress["wallet"]
                private_key = progress["private_key"]
                token_out = progress["token_out"]
                amount = progress["amount"]
                count = progress["count"]
                pool_version = progress.get("pool_version", "v3")
                temp_wallets = progress.get("temp_wallets", [])
                current_index = progress.get("current_index", -1)

                # Sweep all already completed temp wallets before resuming
                completed_wallets = [w for w in temp_wallets if w.get("completed")]
                if completed_wallets:
                    try:
                        w3 = get_user_w3(uid)
                        print(f"[INFO] Sweeping {len(completed_wallets)} completed wallets for {uid} before resume...")
                        await sweep_completed_wallets(w3, completed_wallets, wallet)
                    except Exception as e:
                        print(f"[WARN] Failed to sweep completed wallets for {uid}: {e}")

                # Resume from next swap
                start_index = current_index + 1
                if start_index >= count:
                    print(f"[INFO] All swaps already completed for {uid}, skipping.")
                    continue

                # restore user swap state
                user_swap_state[uid] = {
                    "wallet": wallet,
                    "private_key": private_key,
                    "token_out": token_out,
                    "amount": amount,
                    "count": count,
                    "current_index": current_index,
                    "pool_version": pool_version,
                    "temp_wallets": temp_wallets,
                    "task": None,
                    "cancel": False
                }

                try:
                    await bot.bot.send_message(
                        chat_id=uid,
                        text=(f"⚡ Bot restarted.\n"
                              f"Sry for the inconvenience caused.\n"
                              f"Auto-resuming swaps {start_index + 1}/{count} "
                              f"on {pool_version.upper()}...")
                    )
                except Exception as e:
                    print(f"[WARN] Failed to notify {uid}: {e}")

                # start background task
                task = asyncio.create_task(
                    run_swaps(uid, wallet, private_key, token_out, amount,
                              count, start_index, bot, pool_version=pool_version)
                )
                user_swap_state[uid]["task"] = task
                resumed_any = True

            except Exception as e:
                print(f"[ERROR] Failed to resume swap from {file}: {e}")

    if not resumed_any:
        print("[INFO] No active swaps found. Bot restarted without auto-resume.")


# ================= Cancel Handler ================= #
def log_error_to_file(uid: int, username: str, msg: str):
    """Append errors to a log file with user details + timestamp."""
    with open(ERROR_LOG_FILE, "a") as f:
        f.write(
            f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"User: {username or 'N/A'} (ID: {uid})\n{msg}\n\n"
        )


def clear_user_errors(uid: int, username: str):
    """Remove all error logs related to a specific user from the file."""
    if not os.path.exists(ERROR_LOG_FILE):
        return
    with open(ERROR_LOG_FILE, "r") as f:
        lines = f.readlines()
    with open(ERROR_LOG_FILE, "w") as f:
        skip = False
        for line in lines:
            if f"(ID: {uid})" in line:
                skip = True  # start skipping this block
            elif skip and line.strip() == "":
                skip = False  # stop skipping after blank line
                continue
            if not skip:
                f.write(line)


async def safe_edit(uid, q, msg, text):
    """Safe wrapper for Telegram message edits."""
    try:
        await msg.edit_text(text)
    except Exception as e:
        log_error_to_file(uid, q, f"[⚠️ Telegram Edit Failed] {str(e)}")


async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id

    if uid not in user_swap_state:
        await update.message.reply_text("⚠️ No active swap to cancel.")
        return

    await cancel_swap(uid, context.bot)


async def cancel_swap(uid, bot):
    """
    Cancel the active swap for a user, sweep completed wallets,
    and prevent auto-resume.
    """
    if uid in user_swap_state:
        state = user_swap_state[uid]
        wallet = state.get("wallet")
        private_key = state.get("private_key")
        pool_version = state.get("pool_version", "v3")
        temp_wallets = state.get("temp_wallets", [])

        # ✅ sweep completed wallets so user doesn't lose ETH
        if temp_wallets:
            try:
                w3 = get_user_w3(uid)
                print(f"[INFO] Cancel requested. Sweeping completed wallets for {uid}...")
                await sweep_completed_wallets(w3, temp_wallets, wallet)
            except Exception as e:
                print(f"[WARN] Sweeping during cancel failed for {uid}: {e}")

        # ✅ save progress as canceled so it won't auto-resume
        save_progress(
            uid=uid,
            wallet=wallet,
            private_key=private_key,
            token_out=state.get("token_out"),
            amount=state.get("amount"),
            count=state.get("count"),
            current_index=state.get("current_index", 0),
            pool_version=pool_version,
            temp_wallets=temp_wallets,
            canceled=True
        )

        # set cancel flag
        state["cancel"] = True

        # cancel background task if it exists
        if state.get("task"):
            task = state["task"]
            task.cancel()

        # clean memory state
        user_swap_state.pop(uid, None)

    # notify user
    try:
        await bot.send_message(chat_id=uid,
                               text="❌ Swap canceled. Completed wallets swept, and it will not auto-resume.")
    except Exception as e:
        print(f"[WARN] Failed to notify user {uid} on cancel: {e}")


# ================= Remove Message Handler ================= #
# Step 1: User types /remove
async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    row = get_wallet_row(uid)

    if not row:
        await update.message.reply_text("❌ No wallet found for your account.")
        return

    keyboard = [
        [
            InlineKeyboardButton("✅ Yes, remove", callback_data="confirm_remove"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_remove")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "⚠️ Are you sure you want to remove your wallet?\n"
        "You will **not** be able to access funds if you haven't saved your private key.\n\n"
        "Next time you press /start, a new wallet will be created.",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )


# Step 2: Handle confirm/cancel
async def remove_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    if query.data == "cancel_remove":
        await query.edit_message_text("❌ Wallet removal cancelled.")
        return

    elif query.data == "confirm_remove":
        conn = sqlite3.connect("wallets.db")
        cur = conn.cursor()
        cur.execute("DELETE FROM wallets WHERE telegram_id=?", (uid,))
        conn.commit()
        conn.close()

        await query.edit_message_text(
            "✅ Your wallet has been removed.\n"
            "Press /start to create a new wallet."
        )


# ================= Error Message Handler ================= #
def extract_error_message(e: Exception) -> str:
    """Extract a clean error message from an exception, handling dicts and stringified dicts."""
    err_msg = str(e)  # default fallback

    if hasattr(e, "args") and e.args:
        first = e.args[0]
        if isinstance(first, dict):
            err_msg = first.get("message", str(e))
        elif isinstance(first, str):
            try:
                parsed = ast.literal_eval(first)
                if isinstance(parsed, dict) and "message" in parsed:
                    err_msg = parsed["message"]
            except Exception:
                pass  # fallback to str(e)

    return err_msg


# ================= Show Menu Handlers ================= #
async def show_main_menu(update, context, edit=False):
    keyboard = [
        [InlineKeyboardButton("👛 My Wallet", callback_data="mywallet"),
         InlineKeyboardButton("🔑 Export Key", callback_data="exportkey")],
        [InlineKeyboardButton("💰 Balance", callback_data="balance"),
         InlineKeyboardButton("📥 Deposit", callback_data="deposit")],
        [InlineKeyboardButton("💸 Withdraw", callback_data="withdraw"),
         InlineKeyboardButton("🛒 Buy", callback_data="buy")],
        [InlineKeyboardButton("💱 Sell", callback_data="sell"),
         InlineKeyboardButton("📊 Txn Bot", callback_data="txnbot")],
        [InlineKeyboardButton("❓ Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    # If we have a previous menu message → edit it
    if edit and "menu_msg_id" in context.user_data:
        try:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=context.user_data["menu_msg_id"],
                text="📍 Main Menu:",
                reply_markup=reply_markup
            )
            return
        except Exception:
            pass  # if edit fails (deleted, etc.), fall back to sending new

    # Otherwise → send a fresh menu
    msg = await update.effective_chat.send_message("📍 Main Menu:", reply_markup=reply_markup)
    context.user_data["menu_msg_id"] = msg.message_id


async def menu_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    # Replace menu with processing state
    try:
        await query.edit_message_text(f"⏳ Processing: {data}...")
    except Exception:
        pass

    if data == "mywallet":
        await mywallet_handler(update, context)

    elif data == "exportkey":
        await exportkey_handler(update, context)

    elif data == "balance":
        await balance_handler(update, context)

    elif data == "deposit":
        await deposit_handler(update, context)

    elif data == "buy":
        # let buy_command handle its own conversation
        await buy_command(update, context)

    elif data == "sell":
        await sell_command(update, context)

    elif data == "txnbot":
        await txnbot_command(update, context)

    elif data == "cancel":
        await cancel_handler(update, context)

    elif data == "remove":
        await remove_command(update, context)

    elif data == "help":
        await help_handler(update, context)


# ================= SetCommands Handlers ================= #
async def set_commands(app):
    await app.bot.set_my_commands([
        BotCommand("start", "Start the bot & show menu"),
        BotCommand("mywallet", "Show your wallet address"),
        BotCommand("exportkey", "Export private key"),
        BotCommand("balance", "Check wallet balance"),
        BotCommand("deposit", "Deposit funds"),
        BotCommand("withdraw", "Withdraw funds"),
        BotCommand("buy", "Swap ETH → Token"),
        BotCommand("sell", "Swap Token → ETH"),
        BotCommand("txnbot", "Multi-buy transaction bot"),
        BotCommand("help", "Help & usage guide"),
        BotCommand("cancel", "To cancel any ongoing swaps"),
        BotCommand("remove", "To remove the current wallet from database")
    ])


async def on_startup(app):
    print("🚀 Bot starting... checking for unfinished swaps...")
    await auto_resume_all(app)


# ================= Main ================= #
def main():
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    app = Application.builder().token(TOKEN).post_init(set_commands).post_init(on_startup).read_timeout(
        60).write_timeout(60).build()

    app.add_handler(CommandHandler("start", start_handler))

    # keep your existing handlers for /buy, /sell, /txnbot and their confirm/cancel callbacks
    app.add_handler(CommandHandler("mywallet", mywallet_handler))
    app.add_handler(CommandHandler("exportkey", exportkey_handler))
    app.add_handler(CommandHandler("balance", balance_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("deposit", deposit_handler))
    app.add_handler(withdraw_handler)

    app.add_handler(CommandHandler("buy", buy_command))
    app.add_handler(CallbackQueryHandler(buy_button_handler, pattern="confirm_swap|cancel_swap|pool_v2|pool_v3"))

    app.add_handler(CommandHandler("sell", sell_command))
    app.add_handler(
        CallbackQueryHandler(sell_button_handler, pattern="^confirm_sell|cancel_sell|sell_pool_v2|sell_pool_v3$"))

    app.add_handler(CommandHandler("txnbot", txnbot_command))
    app.add_handler(CallbackQueryHandler(buy_button_handler, pattern="confirm_swap|cancel_swap|pool_v2|pool_v3"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, swap_handle_message))

    app.add_handler(CommandHandler("cancel", cancel_handler))

    app.add_handler(CommandHandler("remove", remove_command))
    app.add_handler(CallbackQueryHandler(remove_button_handler, pattern="^(confirm_remove|cancel_remove)$"))

    app.add_handler(CallbackQueryHandler(menu_button_handler,
                                         pattern="^(mywallet|exportkey|balance|deposit|buy|sell|txnbot|help)$"))

    logger.info("Bot started. Press Ctrl+C to stop.")
    # Run polling asynchronously
    app.run_polling()


if __name__ == "__main__":
    main()
