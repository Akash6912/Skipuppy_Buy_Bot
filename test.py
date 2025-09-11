from web3 import Web3
from eth_account import Account
import json
import os

# --- CONFIG ---
BASE_RPC = "https://base-mainnet.g.alchemy.com/v2/apYsebVqcGrcLLJWLQ77c"  # You can use Alchemy/Infura Base RPC
PRIVATE_KEY = "3af0771d58b01b46d00fe14d95ab2b6d7bbad500a95dc037e36fce771ac9160a"       # ⚠️ Don't share this
ACCOUNT = Account.from_key(PRIVATE_KEY)
ADDRESS = ACCOUNT.address

# Uniswap V2 router on Base (example: Aerodrome router or UniswapV2-style)
ROUTER_ADDRESS = Web3.to_checksum_address("0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24")
# Replace with actual V2 router on Base

# Example token (USDC on Base)
TOKEN_OUT = Web3.to_checksum_address("0x20895E16d5aE9D6e0Ca127ED093a7cBE65dCb018")

w3 = Web3(Web3.HTTPProvider(BASE_RPC))

# --- Load ABI ---
# Minimal ABI for Uniswap V2 router
ROUTER_ABI = json.loads("""
[
  {"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},
             {"internalType":"address[]","name":"path","type":"address[]"},
             {"internalType":"address","name":"to","type":"address"},
             {"internalType":"uint256","name":"deadline","type":"uint256"}],
   "name":"swapExactETHForTokens",
   "outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],
   "stateMutability":"payable","type":"function"}
]
""")

router = w3.eth.contract(address=ROUTER_ADDRESS, abi=ROUTER_ABI)

# --- Build TX ---

# --- Build swap params ---
amount_in_eth = 0.00000003  # ETH to swap
deadline = w3.eth.get_block("latest")["timestamp"] + 60 * 5  # 5 min
WETH = Web3.to_checksum_address("0x4200000000000000000000000000000000000006")
path = [WETH, TOKEN_OUT]

# --- Estimate gas ---
gas_estimate = router.functions.swapExactETHForTokens(
    0, path, ADDRESS, deadline
).estimate_gas({
    "from": ADDRESS,
    "value": w3.to_wei(amount_in_eth, "ether"),
})
print(f"Estimated gas units: {gas_estimate}")

# --- Use Base's legacy gasPrice (cheap & stable) ---
gas_price = w3.eth.gas_price

# --- Estimate cost in ETH & USD ---
eth_price_usd = 4400  # set manually, or fetch from API
fee_eth = gas_estimate * gas_price / 1e18
fee_usd = fee_eth * eth_price_usd
print(f"Estimated tx fee: {fee_eth:.8f} ETH ≈ ${fee_usd:.4f}")

# --- Build transaction ---
txn = router.functions.swapExactETHForTokens(
    0, path, ADDRESS, deadline
).build_transaction({
    "from": ADDRESS,
    "value": w3.to_wei(amount_in_eth, "ether"),
    "gas": int(gas_estimate * 1.2),  # add 20% buffer
    "gasPrice": gas_price,
    "nonce": w3.eth.get_transaction_count(ADDRESS),
    "chainId": 8453,  # Base mainnet
})

# --- Sign & Send ---
signed_txn = w3.eth.account.sign_transaction(txn, private_key=PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

print(f"✅ Swap submitted! Tx hash: {w3.to_hex(tx_hash)}")