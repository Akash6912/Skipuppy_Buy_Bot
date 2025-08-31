from telegram import Update, InputFile, ReplyKeyboardMarkup, ReplyKeyboardRemove, InlineKeyboardMarkup, \
    InlineKeyboardButton, BotCommand
from telegram.ext import Application, ConversationHandler, CommandHandler, MessageHandler, CallbackQueryHandler, \
    filters, ContextTypes
import os, time, requests, qrcode, json, logging, aiohttp, asyncio, sqlite3
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from web3 import Web3
from io import BytesIO
from eth_account import Account
from swapcode import Uniswap
from keep_alive import run_server

load_dotenv(override=True)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# --- Web3 Setup (Base Chain) ---
BASE_RPC = os.getenv("BASE_RPC", os.environ.get("BASE_RPC"))
w3 = Web3(Web3.HTTPProvider(BASE_RPC))


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
FERNET_KEY = os.environ.get("MASTER_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
    print("⚠️ WARNING: Generated new FERNET_KEY. Save this in your .env to keep wallets consistent:", FERNET_KEY)

fernet = Fernet(FERNET_KEY.encode())


def encrypt_privkey(privkey_hex: str) -> str:
    return fernet.encrypt(privkey_hex.encode()).decode()


def decrypt_privkey(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()


# --- START HANDLER ---
async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
        "Choose an option below:",
        reply_markup=reply_markup
    )


# --- Wallet Handlers ---
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
    time.sleep(3)
    await show_main_menu(update, context, edit=True)


# --- ExportKey Handlers ---
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
    time.sleep(3)
    await show_main_menu(update, context, edit=True)


# --- Balance Handlers ---
async def fetch_metadata(session, contract_address):
    """Fetch token metadata from Alchemy for a given contract."""
    meta_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getTokenMetadata",
        "params": [contract_address]
    }
    async with session.post(BASE_RPC, json=meta_payload) as resp:
        try:
            data = await resp.json()
            return contract_address, data.get("result", {})
        except Exception:
            return contract_address, {}


async def balance_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    tid = update.effective_user.id
    row = get_wallet_row(tid)

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
        async with session.post(BASE_RPC, json=payload) as resp:
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
    time.sleep(3)
    await show_main_menu(update, context, edit=True)


# --- Help Handlers ---
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
            "/help: Help & usage guide\n\n"
            "Security reminder: do not share your private key with strangers. Keep the MASTER_KEY safe on the server."
        ),
    )
    time.sleep(3)
    await show_main_menu(update, context, edit=True)


# --- Deposit Handlers ---
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
    time.sleep(3)
    await show_main_menu(update, context, edit=True)

# --- Withdrawl Handlers ---
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
    row = get_wallet_row(tid)  # must return (tid, wallet_address, encrypted_privkey)
    BOT_ADDRESS = row[1]

    try:
        amount = float(update.message.text.strip())
    except ValueError:
        await update.message.reply_text("❌ Invalid number. Please enter a valid amount:")
        return WITHDRAW_AMOUNT

    recipient = context.user_data["address"]

    try:
        # Convert ETH to wei
        value = w3.to_wei(amount, "ether")
        nonce = w3.eth.get_transaction_count(BOT_ADDRESS)

        tx = {
            "to": recipient,
            "value": value,
            "gas": 21000,
            "gasPrice": w3.eth.gas_price,
            "nonce": nonce,
            "chainId": 8453   # Base mainnet
        }

        signed_tx = w3.eth.account.sign_transaction(tx, decrypt_privkey(row[2]))
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        txn_link = f"https://basescan.org/tx/{w3.to_hex(tx_hash)}"
        await update.message.reply_text(f"✅ ETH withdrawal sent!\n🔗 {txn_link}")

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error while sending: {e}")

    time.sleep(3)
    await show_main_menu(update, context, edit=True)
    return ConversationHandler.END


# Step 3: Cancel
async def withdraw_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Withdrawal cancelled.", reply_markup=ReplyKeyboardRemove())
    time.sleep(3)
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
)



# --- Wrap/Unwrap eth Handlers ---
user_swap_state = {}


# WETH contract on Base
WETH_ADDRESS = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
WETH_ABI = [
    {
        "inputs": [],
        "name": "deposit",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "wad", "type": "uint256"}
        ],
        "name": "withdraw",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]


weth_contract = w3.eth.contract(address=WETH_ADDRESS, abi=WETH_ABI)


def wrap_eth_to_weth(private_key: str, amount_eth: float):
    """Wrap ETH into WETH on Base chain."""
    account = Account.from_key(private_key)
    address = account.address

    # Build tx for deposit()
    txn = weth_contract.functions.deposit().build_transaction({
        "from": address,
        "value": w3.to_wei(amount_eth, "ether"),
        "gas": 100000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(address),
        "chainId": 8453  # Base mainnet chainId
    })

    # Sign & send
    signed_txn = w3.eth.account.sign_transaction(txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    return w3.to_hex(tx_hash)


def unwrap_weth_to_eth(private_key: str, amount_eth: float):
    """Unwrap WETH into ETH on Base chain."""
    account = Account.from_key(private_key)
    address = account.address

    txn = weth_contract.functions.withdraw(
        w3.to_wei(amount_eth, "ether")
    ).build_transaction({
        "from": address,
        "gas": 100000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(address),
        "chainId": 8453
    })

    signed_txn = w3.eth.account.sign_transaction(txn, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
    return w3.to_hex(tx_hash)


# --- Buy Handlers ---
async def buy_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("Enter token address:")
    user_swap_state[update.effective_user.id] = {"step": "token_out", "mode": "buy"}


async def swap_handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid not in user_swap_state:
        return

    state = user_swap_state[uid]
    mode = state.get("mode")

    # -------- BUY FLOW --------
    if mode == "buy":
        if state["step"] == "token_out":
            state["token_out"] = update.message.text.strip()
            state["step"] = "amount"
            await update.message.reply_text("Enter ETH amount to swap:")

        elif state["step"] == "amount":
            try:
                amount = float(update.message.text.strip())
                state["amount"] = amount

                keyboard = [[
                    InlineKeyboardButton("✅ Confirm", callback_data="confirm_swap"),
                    InlineKeyboardButton("❌ Cancel", callback_data="cancel_swap")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Swap {amount} ETH → {state['token_out']} ?",
                    reply_markup=reply_markup
                )
                state["step"] = "confirm"
            except ValueError:
                await update.message.reply_text("⚠️ Invalid ETH amount. Enter a number.")

    # -------- SELL FLOW --------
    elif mode == "sell":
        if state["step"] == "token_in":
            state["token_in"] = update.message.text.strip()
            state["step"] = "amount"
            await update.message.reply_text("Enter token amount to sell:")

        elif state["step"] == "amount":
            try:
                amount = float(update.message.text.strip())
                state["amount"] = amount

                keyboard = [[
                    InlineKeyboardButton("✅ Confirm", callback_data="confirm_sell"),
                    InlineKeyboardButton("❌ Cancel", callback_data="cancel_sell")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Sell {amount} of {state['token_in']} → ETH ?",
                    reply_markup=reply_markup
                )
                state["step"] = "confirm"
            except ValueError:
                await update.message.reply_text("⚠️ Invalid token amount. Enter a number.")

    # -------- MULTIPLE SWAPS FLOW (/txnbot) --------
    elif mode == "txnbot":
        if state["step"] == "token_out":
            state["token_out"] = update.message.text.strip()
            state["step"] = "amount"
            await update.message.reply_text("Enter ETH amount to swap each time:")

        elif state["step"] == "amount":
            try:
                state["amount"] = float(update.message.text.strip())
                state["step"] = "count"
                await update.message.reply_text("How many times do you want to swap?")
            except ValueError:
                await update.message.reply_text("⚠️ Invalid amount. Enter a number.")

        elif state["step"] == "count":
            try:
                state["count"] = int(update.message.text.strip())

                keyboard = [[
                    InlineKeyboardButton("✅ Confirm", callback_data="confirm_txnbot"),
                    InlineKeyboardButton("❌ Cancel", callback_data="cancel_txnbot")
                ]]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await update.message.reply_text(
                    f"Swap {state['amount']} ETH → {state['token_out']} "
                    f"{state['count']} times?",
                    reply_markup=reply_markup
                )
                state["step"] = "confirm"
            except ValueError:
                await update.message.reply_text("⚠️ Invalid number. Enter an integer.")


def perform_buy(wallet, private_key, token_out, amount, slippage=0.05):
    tx = wrap_eth_to_weth(private_key, amount)
    time.sleep(1)
    # 3. Instantiate the Uniswap helper
    uniswap = Uniswap(
        wallet_address=wallet,
        private_key=private_key,
        provider=os.environ.get("BASE_RPC"),  # Used to auto-detect chain
        web3=w3
    )

    # 4. Perform a swap (SWAP_EXACT_IN)
    # Example: Swap 1 tokenIn -> tokenOut at 0.3% fee in a v3 pool
    try:
        value = w3.to_wei(amount, "ether")
        tx_hash = uniswap.make_trade(
            from_token="0x4200000000000000000000000000000000000006",
            to_token=token_out,
            amount=value,
            fee=10000,  # e.g., 3000 for a 0.3% Uniswap V3 pool
            slippage=2,  # non-functional right now. 0.5% slippage tolerance
            pool_version="v3"  # can be "v3" or "v4"
        )
        print(f"Swap transaction sent! Tx hash: {tx_hash.hex()}")
        return f"✅ Swap successful!\n🔗 https://basescan.org/tx/0x{tx_hash.hex()}"
    except Exception as e:
        return


# --- Sell Handlers ---
def get_eth_balance(address):
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


async def sell_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("Enter token address to sell:")
    user_swap_state[update.effective_user.id] = {"step": "token_in", "mode": "sell"}


async def sell_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    tid = update.effective_user.id
    row = get_wallet_row(tid)
    if uid not in user_swap_state:
        return

    state = user_swap_state[uid]

    if query.data == "cancel_sell":
        await query.edit_message_text("❌ Sell cancelled.")
        user_swap_state.pop(uid, None)

    elif query.data == "confirm_sell":
        wallet = row[1]
        private_key = decrypt_privkey(row[2])

        token_in = state["token_in"]
        amount = state["amount"]

        await query.edit_message_text("⏳ Selling token...")

        try:
            result = perform_sell(wallet, private_key, token_in, amount)
            await context.bot.send_message(
                chat_id=query.message.chat_id,
                text=result
            )
            if result == -1:
                raise ValueError("Sell returned no result.")
        except Exception as e:
            await context.bot.send_message(
                chat_id=query.message.chat_id,
                text=f"⚠️ Sell failed.\nError: {str(e)}"
            )
        time.sleep(3)
        await show_main_menu(update, context, edit=True)
        user_swap_state.pop(uid, None)


def perform_sell(wallet, private_key, token_in, amount, slippage=0.05):
    # Instantiate Uniswap helper
    uniswap = Uniswap(
        wallet_address=wallet,
        private_key=private_key,
        provider=os.environ.get("BASE_RPC"),
        web3=w3
    )

    try:
        value = w3.to_wei(amount, "ether")  # assumes 18 decimals, adjust for tokens like USDC (6 decimals)
        tx_hash = uniswap.make_trade(
            from_token=token_in,
            to_token="0x4200000000000000000000000000000000000006",  # WETH
            amount=value,
            fee=10000,   # 1% pool, adjust to 3000 (0.3%) or 500 (0.05%) depending on liquidity
            slippage=2,
            pool_version="v3"
        )
        print(f"Sell transaction sent! Tx hash: {tx_hash.hex()}")
        time.sleep(1)
        if get_eth_balance(wallet) > 0:
            unwrap_weth_to_eth(private_key, get_eth_balance(wallet))
            return f"✅ Sell successful!\n🔗 https://basescan.org/tx/0x{tx_hash.hex()}"
    except Exception as e:
        print(f"Sell failed: {e}")
        return -1


# ================= TXNBOT MULTIPLE SWAPS ================= #

async def txnbot_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text("Enter token address for multiple swaps:")
    user_swap_state[update.effective_user.id] = {"step": "token_out", "mode": "txnbot"}


async def buy_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id
    tid = uid

    row = get_wallet_row(tid)
    if uid not in user_swap_state:
        return

    state = user_swap_state[uid]

    if query.data.startswith("cancel_"):
        await query.edit_message_text("❌ Cancelled.")
        user_swap_state.pop(uid, None)
        return

    wallet = row[1]
    private_key = decrypt_privkey(row[2])

    # ---------------- SINGLE BUY ---------------- #
    if query.data == "confirm_swap" and state.get("mode") == "buy":
        token_out = state["token_out"]
        amount = state["amount"]

        await query.edit_message_text("⏳ Swapping ETH...")
        try:
            result = perform_buy(wallet, private_key, token_out, amount)
            if result == -1:
                raise ValueError("Swap failed")
            await context.bot.send_message(chat_id=query.message.chat_id, text=result)
        except Exception as e:
            await context.bot.send_message(chat_id=query.message.chat_id, text=f"⚠️ Swap failed.\nError: {str(e)}")

        time.sleep(3)
        await show_main_menu(update, context, edit=True)
        user_swap_state.pop(uid, None)

    # ---------------- MULTIPLE SWAPS ---------------- #
    elif query.data == "confirm_txnbot" and state.get("mode") == "txnbot":
        token_out = state["token_out"]
        amount = state["amount"]
        count = state["count"]

        await query.edit_message_text(f"⏳ Starting {count} swaps...")

        msg = await context.bot.send_message(chat_id=query.message.chat_id, text="Swaps in progress...")

        success_count = 0
        for i in range(count):
            try:
                result = perform_buy(wallet, private_key, token_out, amount)
                time.sleep(10)
                if result != -1:
                    success_count += 1
                    await msg.edit_text(f"✅ Swapped ETH {i+1} times")
                else:
                    await msg.edit_text(f"⚠️ Swap {i+1} failed")
            except Exception as e:
                await msg.edit_text(f"⚠️ Swap {i+1} failed: {str(e)}")
                return

              # delay between swaps

        await msg.edit_text(f"🎉 Completed {success_count}/{count} swaps")
        time.sleep(3)
        await show_main_menu(update, context, edit=True)
        user_swap_state.pop(uid, None)


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



# --- BUTTON HANDLER (redirects inline button clicks to commands) ---
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

    elif data == "help":
        await help_handler(update, context)




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
        BotCommand("help", "Help & usage guide")
    ])


# --- Main ---
def main():
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    app = Application.builder().token(TOKEN).build()

    run_server(10000)  # port must match Render port

    app.add_handler(CommandHandler("start", start_handler))

    # keep your existing handlers for /buy, /sell, /txnbot and their confirm/cancel callbacks
    app.add_handler(CommandHandler("mywallet", mywallet_handler))
    app.add_handler(CommandHandler("exportkey", exportkey_handler))
    app.add_handler(CommandHandler("balance", balance_handler))
    app.add_handler(CommandHandler("help", help_handler))
    app.add_handler(CommandHandler("deposit", deposit_handler))
    app.add_handler(withdraw_handler)

    app.add_handler(CommandHandler("buy", buy_command))
    app.add_handler(CallbackQueryHandler(buy_button_handler, pattern="confirm_swap|cancel_swap"))

    app.add_handler(CommandHandler("sell", sell_command))
    app.add_handler(CallbackQueryHandler(sell_button_handler, pattern="confirm_sell|cancel_sell"))

    app.add_handler(CommandHandler("txnbot", txnbot_command))
    app.add_handler(CallbackQueryHandler(buy_button_handler, pattern="^(confirm_txnbot|cancel_txnbot)$"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, swap_handle_message))

    app.add_handler(CallbackQueryHandler(menu_button_handler,
                                         pattern="^(mywallet|exportkey|balance|deposit|buy|sell|txnbot|help)$"))



    logger.info("Bot started. Press Ctrl+C to stop.")
    app.run_polling()

    # Register commands to Telegram menu when bot starts
    app.post_init.append(set_commands)

    app.idle()


if __name__ == "__main__":
    main()
