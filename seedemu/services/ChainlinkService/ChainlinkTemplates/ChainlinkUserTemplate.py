from typing import Dict

ChainlinkUserTemplate: Dict[str, str] = {}

ChainlinkUserTemplate['get_contract_addresses']="""\
#!/bin/env python3

import requests
import re
import logging
import time
import json
import os

def check_oracle_contracts(init_server_url, number_of_normal_servers):
    oracle_contracts_found = 0
    link_token_contract_address = None

    while oracle_contracts_found != number_of_normal_servers:
        try:
            response = requests.get(init_server_url)
            if response and response.status_code == 200:
                html_content = response.text

                oracle_contracts = re.findall(r'<h1>Oracle Contract Address: (.+?)</h1>', html_content)
                oracle_contracts_found = len(oracle_contracts)
                logging.info(f"Checking for oracle contracts, found: {{oracle_contracts_found}}")

                match = re.search(r'<h1>Link Token Contract: (.+?)</h1>', html_content)
                if match and match.group(1):
                    link_token_contract_address = match.group(1)
                    logging.info(f"Found Link Token address: {{link_token_contract_address}}")

                if oracle_contracts_found == number_of_normal_servers:
                    logging.info("Found all required oracle contracts.")
                    break
                else:
                    logging.info(f"Number of oracle contracts found ({{oracle_contracts_found}}) does not match the target ({{number_of_normal_servers}}). Retrying...")
            else:
                logging.warning("Failed to fetch data from server. Retrying...")

        except Exception as e:
            logging.error(f"An error occurred: {{e}}")

        # Wait 30 seconds before retrying
        time.sleep(30)

    return oracle_contracts, link_token_contract_address

init_server_url = "http://{init_node_url}"
number_of_normal_servers = {number_of_normal_servers}
oracle_contracts, link_token_contract_address = check_oracle_contracts(init_server_url, number_of_normal_servers)
logging.info(f"Oracle Contracts: {{oracle_contracts}}")
logging.info(f"Link Token Contract Address: {{link_token_contract_address}}")
# Save this information to a file
data = {{
    'oracle_contracts': oracle_contracts,
    'link_token_contract_address': link_token_contract_address
}}
directory = './info'
if not os.path.exists(directory):
    os.makedirs(directory)
    
with open('./info/contract_addresses.json', 'w') as f:
    json.dump(data, f)
"""

ChainlinkUserTemplate['deploy_user_contract']='''\
#!/bin/env python3

import time
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import requests
import logging
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

rpc_url = "http://{rpc_url}:{rpc_port}"
faucet_url = "http://{faucet_url}:{faucet_port}"

web3 = Web3(HTTPProvider(rpc_url))
while not web3.isConnected():
    logging.error("Failed to connect to Ethereum node. Retrying...")
    time.sleep(5)

web3.middleware_onion.inject(geth_poa_middleware, layer=0)
logging.info("Successfully connected to the Ethereum node.")

user_account = web3.eth.account.create()
account_address = user_account.address
private_key = user_account.privateKey.hex()

# Save user account information to a file
data = {{
    'account_address': account_address,
    'private_key': private_key
}}
with open('./info/user_account.json', 'w') as f:
    json.dump(data, f)
    
logging.info(f"User account address: {{account_address}}")

# Check if the faucet server is running for 600 seconds
timeout = 600
start_time = time.time()
while True:
    try:
        response = requests.get(faucet_url)
        if response.status_code == 200:
            break
    except Exception as e:
        pass

def send_fundme_request(account_address):
	data = {{'address': account_address, 'amount': 10}}
	logging.info(data)
	request_url = "http://{faucet_url}:{faucet_port}/fundme"
	try:
		response = requests.post(request_url, headers={{"Content-Type": "application/json"}}, data=json.dumps(data))
		logging.info(response)
		if response.status_code == 200:
			api_response = response.json()
			message = api_response['message']
			if message:
				print(f"Success: {{message}}")
			else:
				logging.error("Funds request was successful but the response format is unexpected.")
		else:
			api_response = response.json()
			message = api_response['message']
			logging.error(f"Failed to request funds from faucet server. Status code: {{response.status_code}} Message: {{message}}")
			# Send another request
			logging.info("Sending another request to faucet server.")
			send_fundme_request(account_address)
	except Exception as e:
		logging.error(f"An error occurred: {{str(e)}}")
		exit()

# Send /fundme request to faucet server
send_fundme_request(account_address)
timeout = 100
isAccountFunded = False
start = time.time()
while time.time() - start < timeout:
	balance = web3.eth.get_balance(account_address)
	if balance > 0:
		isAccountFunded = True
		break
	time.sleep(5)
 

if isAccountFunded:
	logging.info(f"Account funded: {{account_address}}")
else:
	logging.error(f"Failed to fund account: {{account_address}}")
	exit()

with open('./contracts/user_contract.abi', 'r') as abi_file:
	user_contract_abi = abi_file.read()
with open('./contracts/user_contract.bin', 'r') as bin_file:
	user_contract_bin = bin_file.read().strip()

user_contract = web3.eth.contract(abi=user_contract_abi, bytecode=user_contract_bin)

# Deploy the user contract
user_contract_data = user_contract.constructor().buildTransaction({{
    'from': account_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
}})['data']

def sendTransaction(recipient, amount, sender_name='', 
            gas=30000, nonce:int=-1, data:str='', 
            maxFeePerGas:float=3.0, maxPriorityFeePerGas:float=2.0, 
            wait=True, verbose=True):
    if nonce == -1:
        nonce = web3.eth.getTransactionCount(account_address)
    
    maxFeePerGas = Web3.toWei(maxFeePerGas, 'gwei')
    maxPriorityFeePerGas = Web3.toWei(maxPriorityFeePerGas, 'gwei')
    transaction = {{
        'nonce':    nonce,
        'from':     account_address,
        'to':       recipient,
        'value':    0,
        'chainId':  {chain_id},
        'gas':      gas,
        'maxFeePerGas':         maxFeePerGas,
        'maxPriorityFeePerGas': maxPriorityFeePerGas,
        'data':     data
    }}

    tx_hash = sendRawTransaction(private_key, transaction, wait, verbose)
    return tx_hash

def sendRawTransaction(key, transaction:dict, wait=True, verbose=True):
    signed_tx = web3.eth.account.sign_transaction(transaction, key)
    tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
    if wait:
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_hash

tx_hash = sendTransaction(None, 0, '', gas=3000000, data=user_contract_data, wait=True, verbose=True)
contract_address = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300).contractAddress
logging.info(f"User contract deployed at address: {{contract_address}}")

# Save the contract address to a file
data = {{'contract_address': contract_address}}
with open('./info/user_contract.json', 'w') as f:
    json.dump(data, f)
'''

ChainlinkUserTemplate['set_contract_addresses']='''\
#!/bin/env python3

import time
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import requests
import logging
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

rpc_url = "http://{rpc_url}:{rpc_port}"
faucet_url = "http://{faucet_url}:{faucet_port}"

web3 = Web3(HTTPProvider(rpc_url))
while not web3.isConnected():
    logging.error("Failed to connect to Ethereum node. Retrying...")
    time.sleep(5)

web3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Load the oracle contracts and link token contract address
with open('./info/contract_addresses.json', 'r') as f:
    contract_addresses = json.load(f)
    
oracle_contracts = contract_addresses.get('oracle_contracts', [])
link_token_contract_address = contract_addresses.get('link_token_contract_address', '')

# Load user account information
with open('./info/user_account.json', 'r') as f:
    user_account = json.load(f)
    
account_address = user_account.get('account_address', '')
private_key = user_account.get('private_key', '')

# Load the user contract address
with open('./info/user_contract.json', 'r') as f:
    user_contract = json.load(f)

user_contract_address = user_contract.get('contract_address', '')

# Load the user contract ABI
with open('./contracts/user_contract.abi', 'r') as f:
    user_contract_abi = f.read()

user_contract = web3.eth.contract(address=user_contract_address, abi=user_contract_abi)
set_link_token_function = user_contract.functions.setLinkToken(link_token_contract_address)
transaction_info = {{
    'from': account_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
    'chainId': {chain_id}
}}
set_link_token_tx = set_link_token_function.buildTransaction(transaction_info)
signed_tx = web3.eth.account.sign_transaction(set_link_token_tx, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
if tx_receipt['status'] == 0:
    logging.error("Failed to set Link Token contract address in user contract.")
    exit()
logging.info("Set Link Token contract address in user contract mined successfully.")

# Set the oracle contracts in the user contract
job_id = "7599d3c8f31e4ce78ad2b790cbcfc673"
add_oracle_function = user_contract.functions.addOracles(oracle_contracts, job_id)
transaction_info = {{
    'from': account_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
    'chainId': {chain_id}
}}
add_oracle_tx = add_oracle_function.buildTransaction(transaction_info)
signed_tx = web3.eth.account.sign_transaction(add_oracle_tx, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
# If the status is 0, the transaction failed
if tx_receipt['status'] == 0:
    logging.error("Failed to set oracle contracts in user contract.")
    exit()
logging.info("Add oracles function in user contract mined successfully.")
'''

ChainlinkUserTemplate['fund_user_contract']='''\
#!/bin/env python3

import time
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import requests
import logging
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

rpc_url = "http://{rpc_url}:{rpc_port}"
faucet_url = "http://{faucet_url}:{faucet_port}"

web3 = Web3(HTTPProvider(rpc_url))
while not web3.isConnected():
    logging.error("Failed to connect to Ethereum node. Retrying...")
    time.sleep(5)

web3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Load user account information
with open('./info/user_account.json', 'r') as f:
	user_account = json.load(f)

account_address = user_account.get('account_address', '')
private_key = user_account.get('private_key', '')

link_token_abi = None
with open('./contracts/link_token.abi', 'r') as f:
	link_token_abi = f.read()

# Load the link token contract address
with open('./info/contract_addresses.json', 'r') as f:
	contract_addresses = json.load(f)

link_token_contract_address = contract_addresses.get('link_token_contract_address', '')
link_token_contract_address = web3.toChecksumAddress(link_token_contract_address)

link_token_contract = web3.eth.contract(address=link_token_contract_address, abi=link_token_abi)

transaction_info = {{
    'from': account_address,
    'to': link_token_contract_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
    'gasPrice': web3.toWei(50, 'gwei'),
    'value': web3.toWei(1, 'ether'),
    'chainId': {chain_id}
}}
signed_tx = web3.eth.account.sign_transaction(transaction_info, private_key)
eth_to_link_tx = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
eth_to_link_tx_receipt = web3.eth.wait_for_transaction_receipt(eth_to_link_tx, timeout=300)
if eth_to_link_tx_receipt['status'] == 0:
	logging.error("Failed to send 1 ETH to LINK token contract.")
	exit()
logging.info("Sent 1 ETH to LINK token contract successfully.")

# Transfer 100 LINK tokens to the user contract
with open('./info/user_contract.json', 'r') as f:
	user_contract = json.load(f)

user_contract_address = user_contract.get('contract_address', '')
user_contract_address = web3.toChecksumAddress(user_contract_address)

link_amount_to_transfer = web3.toWei(100, 'ether')
transfer_function = link_token_contract.functions.transfer(user_contract_address, link_amount_to_transfer)
transaction_info = {{
    'from': account_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
    'chainId': {chain_id}
}}
transfer_tx = transfer_function.buildTransaction(transaction_info)
signed_tx = web3.eth.account.sign_transaction(transfer_tx, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
if tx_receipt['status'] == 0:
	logging.error("Failed to transfer LINK tokens to user contract.")
	exit()
logging.info("Transferred LINK tokens to user contract successfully.")

# Check the balance of user contract
balance = link_token_contract.functions.balanceOf(user_contract_address).call()
logging.info(f"User contract balance: {{balance}}")
'''

ChainlinkUserTemplate['request_eth_price']='''\
#!/bin/env python3

import time
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import requests
import logging
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

rpc_url = "http://{rpc_url}:{rpc_port}"
faucet_url = "http://{faucet_url}:{faucet_port}"

web3 = Web3(HTTPProvider(rpc_url))
while not web3.isConnected():
    logging.error("Failed to connect to Ethereum node. Retrying...")
    time.sleep(5)

web3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Load user account information
with open('./info/user_account.json', 'r') as f:
	user_account = json.load(f)

account_address = user_account.get('account_address', '')
private_key = user_account.get('private_key', '')


# Load the user contract address
with open('./info/user_contract.json', 'r') as f:
    user_contract = json.load(f)

user_contract_address = user_contract.get('contract_address', '')

# Load the user contract ABI
with open('./contracts/user_contract.abi', 'r') as f:
    user_contract_abi = f.read()

user_contract = web3.eth.contract(address=user_contract_address, abi=user_contract_abi)
request_eth_price_data_function = user_contract.functions.requestETHPriceData("{url}", "{path}")
transaction_info = {{
    'from': account_address,
    'nonce': web3.eth.getTransactionCount(account_address),
    'gas': 3000000,
    'chainId': {chain_id}
}}
invoke_request_eth_price_data_tx = request_eth_price_data_function.buildTransaction(transaction_info)
signed_tx = web3.eth.account.sign_transaction(invoke_request_eth_price_data_tx, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
if tx_receipt['status'] == 0:
	logging.error("Failed to request ETH price data.")
	exit()
logging.info("Requested ETH price data successfully.")

# Wait for responses to be received
response_count = 0
while response_count < {number_of_normal_servers}:
	response_count = user_contract.functions.responsesCount().call()
	logging.info(f"Awaiting responses... Current responses count: {{response_count}}")
	time.sleep(10)

average_price = user_contract.functions.averagePrice().call()
logging.info(f"Response count: {{response_count}}")
logging.info(f"Average ETH price: {{average_price}}")
logging.info("Chainlink user example service completed.")
'''

ChainlinkUserTemplate['user_contract_abi']="""\
[
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			}
		],
		"name": "OwnableInvalidOwner",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "OwnableUnauthorizedAccount",
		"type": "error"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "id",
				"type": "bytes32"
			}
		],
		"name": "ChainlinkCancelled",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "id",
				"type": "bytes32"
			}
		],
		"name": "ChainlinkFulfilled",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "id",
				"type": "bytes32"
			}
		],
		"name": "ChainlinkRequested",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "previousOwner",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "OwnershipTransferred",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "_oracle",
				"type": "address"
			},
			{
				"internalType": "string",
				"name": "_jobId",
				"type": "string"
			}
		],
		"name": "addOracle",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address[]",
				"name": "_oracles",
				"type": "address[]"
			},
			{
				"internalType": "string",
				"name": "_jobId",
				"type": "string"
			}
		],
		"name": "addOracles",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "averagePrice",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_index",
				"type": "uint256"
			}
		],
		"name": "deactivateOracle",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_requestId",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "_price",
				"type": "uint256"
			}
		],
		"name": "fulfill",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getResponsesCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "linkToken",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "oracles",
		"outputs": [
			{
				"internalType": "address",
				"name": "oracle",
				"type": "address"
			},
			{
				"internalType": "bytes32",
				"name": "jobId",
				"type": "bytes32"
			},
			{
				"internalType": "bool",
				"name": "isActive",
				"type": "bool"
			},
			{
				"internalType": "uint256",
				"name": "price",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "renounceOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "url",
				"type": "string"
			},
			{
				"internalType": "string",
				"name": "path",
				"type": "string"
			}
		],
		"name": "requestETHPriceData",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "responsesCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "_link_token",
				"type": "address"
			}
		],
		"name": "setLinkToken",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "transferOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"stateMutability": "payable",
		"type": "receive"
	}
]
"""

ChainlinkUserTemplate['user_contract_bin']="""\
6080604052600160045534801561001557600080fd5b5033600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036100895760006040517f1e4fbdf700000000000000000000000000000000000000000000000000000000815260040161008091906101a5565b60405180910390fd5b6100988161009e60201b60201c565b506101c0565b6000600660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600660006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061018f82610164565b9050919050565b61019f81610184565b82525050565b60006020820190506101ba6000830184610196565b92915050565b612799806101cf6000396000f3fe6080604052600436106100e15760003560e01c80637ca9a7901161007f5780639c24ea40116100595780639c24ea4014610294578063a0352ea3146102bd578063e67f54f8146102e8578063f2fde38b14610311576100e8565b80637ca9a790146102155780637f525a8a146102405780638da5cb5b14610269576100e8565b806357970e93116100bb57806357970e931461016a5780635b69a7d8146101955780636af6e5ff146101d5578063715018a6146101fe576100e8565b8063071a56df146100ed57806322d277b2146101165780634357855e14610141576100e8565b366100e857005b600080fd5b3480156100f957600080fd5b50610114600480360381019061010f9190611b12565b61033a565b005b34801561012257600080fd5b5061012b610437565b6040516101389190611b87565b60405180910390f35b34801561014d57600080fd5b5061016860048036038101906101639190611c04565b61043d565b005b34801561017657600080fd5b5061017f6107c5565b60405161018c9190611c53565b60405180910390f35b3480156101a157600080fd5b506101bc60048036038101906101b79190611c6e565b6107eb565b6040516101cc9493929190611cc5565b60405180910390f35b3480156101e157600080fd5b506101fc60048036038101906101f79190611dd2565b610858565b005b34801561020a57600080fd5b50610213610989565b005b34801561022157600080fd5b5061022a61099d565b6040516102379190611b87565b60405180910390f35b34801561024c57600080fd5b5061026760048036038101906102629190611e4a565b6109a7565b005b34801561027557600080fd5b5061027e610bae565b60405161028b9190611c53565b60405180910390f35b3480156102a057600080fd5b506102bb60048036038101906102b69190611ec2565b610bd8565b005b3480156102c957600080fd5b506102d2610c2d565b6040516102df9190611b87565b60405180910390f35b3480156102f457600080fd5b5061030f600480360381019061030a9190611c6e565b610c33565b005b34801561031d57600080fd5b5061033860048036038101906103339190611ec2565b610cc3565b005b610342610d49565b600061034d82610dd0565b9050600a60405180608001604052808573ffffffffffffffffffffffffffffffffffffffff1681526020018381526020016001151581526020016000815250908060018154018082558091505060019003906000526020600020906004020160009091909190915060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506020820151816001015560408201518160020160006101000a81548160ff021916908315150217905550606082015181600301555050505050565b60085481565b816005600082815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146104df576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016104d690611f72565b60405180910390fd5b6005600082815260200190815260200160002060006101000a81549073ffffffffffffffffffffffffffffffffffffffff0219169055807f7cc135e0cebb02c3480ae5d74d377283180a2601f8f644edf7987b009316c63a60405160405180910390a2600b600084815260200190815260200160002060009054906101000a900460ff166105a2576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161059990611fde565b60405180910390fd5b6000600b600085815260200190815260200160002060006101000a81548160ff02191690831515021790555060008060005b600a805490508110156106d1573373ffffffffffffffffffffffffffffffffffffffff16600a828154811061060c5761060b611ffe565b5b906000526020600020906004020160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161480156106905750600a81815481106106705761066f611ffe565b5b906000526020600020906004020160020160009054906101000a900460ff165b156106c45784600a82815481106106aa576106a9611ffe565b5b9060005260206000209060040201600301819055506106d1565b80806001019150506105d4565b5060005b600a8054905081101561079a57600a81815481106106f6576106f5611ffe565b5b906000526020600020906004020160020160009054906101000a900460ff16801561074657506000600a828154811061073257610731611ffe565b5b906000526020600020906004020160030154115b1561078d57600a818154811061075f5761075e611ffe565b5b9060005260206000209060040201600301548361077c919061205c565b9250818061078990612090565b9250505b80806001019150506106d5565b5060008111156107be5780826107b09190612107565b600781905550806008819055505b5050505050565b600960009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600a81815481106107fb57600080fd5b90600052602060002090600402016000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010154908060020160009054906101000a900460ff16908060030154905084565b610860610d49565b600061086b82610dd0565b905060005b835181101561098357600a604051806080016040528086848151811061089957610898611ffe565b5b602002602001015173ffffffffffffffffffffffffffffffffffffffff1681526020018481526020016001151581526020016000815250908060018154018082558091505060019003906000526020600020906004020160009091909190915060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506020820151816001015560408201518160020160006101000a81548160ff0219169083151502179055506060820151816003015550508080600101915050610870565b50505050565b610991610d49565b61099b6000610df9565b565b6000600854905090565b6109af610d49565b60005b600a80549050811015610ba957600a81815481106109d3576109d2611ffe565b5b906000526020600020906004020160020160009054906101000a900460ff1615610b9c576000610a30600a8381548110610a1057610a0f611ffe565b5b90600052602060002090600402016001015430634357855e60e01b610ebf565b9050610a7c6040518060400160405280600381526020017f67657400000000000000000000000000000000000000000000000000000000008152508583610ef09092919063ffffffff16565b610ac66040518060400160405280600481526020017f70617468000000000000000000000000000000000000000000000000000000008152508483610ef09092919063ffffffff16565b610b116040518060400160405280600881526020017f6d756c7469706c79000000000000000000000000000000000000000000000000815250606483610f239092919063ffffffff16565b6000610b6b600a8481548110610b2a57610b29611ffe565b5b906000526020600020906004020160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16836712dfb0cb5e880000610f56565b90506001600b600083815260200190815260200160002060006101000a81548160ff02191690831515021790555050505b80806001019150506109b2565b505050565b6000600660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b610be0610d49565b610be981611022565b80600960006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b60075481565b610c3b610d49565b600a805490508110610c82576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610c7990612184565b60405180910390fd5b6000600a8281548110610c9857610c97611ffe565b5b906000526020600020906004020160020160006101000a81548160ff02191690831515021790555050565b610ccb610d49565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610d3d5760006040517f1e4fbdf7000000000000000000000000000000000000000000000000000000008152600401610d349190611c53565b60405180910390fd5b610d4681610df9565b50565b610d51611066565b73ffffffffffffffffffffffffffffffffffffffff16610d6f610bae565b73ffffffffffffffffffffffffffffffffffffffff1614610dce57610d92611066565b6040517f118cdaa7000000000000000000000000000000000000000000000000000000008152600401610dc59190611c53565b60405180910390fd5b565b6000808290506000815103610deb576000801b915050610df4565b60208301519150505b919050565b6000600660009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600660006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b610ec76118d3565b610ecf6118d3565b610ee68585858461106e909392919063ffffffff16565b9150509392505050565b610f0782846080015161111e90919063ffffffff16565b610f1e81846080015161111e90919063ffffffff16565b505050565b610f3a82846080015161111e90919063ffffffff16565b610f5181846080015161114390919063ffffffff16565b505050565b6000806004549050600181610f6b919061205c565b6004819055506000634042994660e01b60008087600001513089604001518760018c6080015160000151604051602401610fac98979695949392919061225e565b604051602081830303815290604052907bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050509050611017868386846111f0565b925050509392505050565b80600260006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600033905090565b6110766118d3565b6110868560800151610100611385565b508385600001818152505082856020019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508185604001907bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191690817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681525050849050949350505050565b61112b82600383516113ef565b61113e818361157490919063ffffffff16565b505050565b7fffffffffffffffffffffffffffffffffffffffffffffffff000000000000000081121561117a576111758282611596565b6111ec565b67ffffffffffffffff81131561119957611194828261160d565b6111eb565b600081126111b2576111ad826000836113ef565b6111ea565b6111e9826001837fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6111e491906122ed565b6113ef565b5b5b5b5050565b600030846040516020016112059291906123e9565b604051602081830303815290604052805190602001209050846005600083815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550807fb5e6e01e79f91267dc17b4e6314d5d4d03593d2ceee0fbb452b750bd70ea5af960405160405180910390a2600260009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16634000aea08685856040518463ffffffff1660e01b81526004016112fb93929190612415565b6020604051808303816000875af115801561131a573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061133e919061247f565b61137d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016113749061251e565b60405180910390fd5b949350505050565b61138d611940565b600060208361139c919061253e565b146113c8576020826113ae919061253e565b60206113ba919061256f565b826113c5919061205c565b91505b81836020018181525050604051808452600081528281016020016040525082905092915050565b60178167ffffffffffffffff1611611426576114208160058460ff16901b60ff16178461165990919063ffffffff16565b5061156f565b60ff8167ffffffffffffffff161161147c57611455601860058460ff16901b178461165990919063ffffffff16565b506114768167ffffffffffffffff166001856116799092919063ffffffff16565b5061156e565b61ffff8167ffffffffffffffff16116114d3576114ac601960058460ff16901b178461165990919063ffffffff16565b506114cd8167ffffffffffffffff166002856116799092919063ffffffff16565b5061156d565b63ffffffff8167ffffffffffffffff161161152c57611505601a60058460ff16901b178461165990919063ffffffff16565b506115268167ffffffffffffffff166004856116799092919063ffffffff16565b5061156c565b611549601b60058460ff16901b178461165990919063ffffffff16565b5061156a8167ffffffffffffffff166008856116799092919063ffffffff16565b505b5b5b5b505050565b61157c611940565b61158e8384600001515184855161169b565b905092915050565b6115b460036005600660ff16901b178361165990919063ffffffff16565b5061160982827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6115e591906122ed565b6040516020016115f59190611b87565b60405160208183030381529060405261178a565b5050565b61162b60026005600660ff16901b178361165990919063ffffffff16565b5061165582826040516020016116419190611b87565b60405160208183030381529060405261178a565b5050565b611661611940565b61167183846000015151846117af565b905092915050565b611681611940565b611692848560000151518585611805565b90509392505050565b6116a3611940565b82518211156116b157600080fd5b846020015182856116c2919061205c565b11156116f7576116f68560026116e7886020015188876116e2919061205c565b611893565b6116f191906125a3565b6118af565b5b6000808651805187602083010193508088870111156117165787860182525b60208701925050505b6020841061175d5780518252602082611738919061205c565b9150602081611747919061205c565b9050602084611756919061256f565b935061171f565b60006001856020036101000a03905080198251168184511681811785525050508692505050949350505050565b61179782600283516113ef565b6117aa818361157490919063ffffffff16565b505050565b6117b7611940565b836020015183106117dd576117dc84600286602001516117d791906125a3565b6118af565b5b835180516020858301018481538186036117f8576001820183525b5050508390509392505050565b61180d611940565b8460200151848361181e919061205c565b1115611846576118458560028685611836919061205c565b61184091906125a3565b6118af565b5b60006001836101006118589190612718565b611862919061256f565b905085518386820101858319825116178152815185880111156118855784870182525b505085915050949350505050565b6000818311156118a5578290506118a9565b8190505b92915050565b6000826000015190506118c28383611385565b506118cd8382611574565b50505050565b6040518060a0016040528060008019168152602001600073ffffffffffffffffffffffffffffffffffffffff16815260200160007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191681526020016000815260200161193a611940565b81525090565b604051806040016040528060608152602001600081525090565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006119998261196e565b9050919050565b6119a98161198e565b81146119b457600080fd5b50565b6000813590506119c6816119a0565b92915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611a1f826119d6565b810181811067ffffffffffffffff82111715611a3e57611a3d6119e7565b5b80604052505050565b6000611a5161195a565b9050611a5d8282611a16565b919050565b600067ffffffffffffffff821115611a7d57611a7c6119e7565b5b611a86826119d6565b9050602081019050919050565b82818337600083830152505050565b6000611ab5611ab084611a62565b611a47565b905082815260208101848484011115611ad157611ad06119d1565b5b611adc848285611a93565b509392505050565b600082601f830112611af957611af86119cc565b5b8135611b09848260208601611aa2565b91505092915050565b60008060408385031215611b2957611b28611964565b5b6000611b37858286016119b7565b925050602083013567ffffffffffffffff811115611b5857611b57611969565b5b611b6485828601611ae4565b9150509250929050565b6000819050919050565b611b8181611b6e565b82525050565b6000602082019050611b9c6000830184611b78565b92915050565b6000819050919050565b611bb581611ba2565b8114611bc057600080fd5b50565b600081359050611bd281611bac565b92915050565b611be181611b6e565b8114611bec57600080fd5b50565b600081359050611bfe81611bd8565b92915050565b60008060408385031215611c1b57611c1a611964565b5b6000611c2985828601611bc3565b9250506020611c3a85828601611bef565b9150509250929050565b611c4d8161198e565b82525050565b6000602082019050611c686000830184611c44565b92915050565b600060208284031215611c8457611c83611964565b5b6000611c9284828501611bef565b91505092915050565b611ca481611ba2565b82525050565b60008115159050919050565b611cbf81611caa565b82525050565b6000608082019050611cda6000830187611c44565b611ce76020830186611c9b565b611cf46040830185611cb6565b611d016060830184611b78565b95945050505050565b600067ffffffffffffffff821115611d2557611d246119e7565b5b602082029050602081019050919050565b600080fd5b6000611d4e611d4984611d0a565b611a47565b90508083825260208201905060208402830185811115611d7157611d70611d36565b5b835b81811015611d9a5780611d8688826119b7565b845260208401935050602081019050611d73565b5050509392505050565b600082601f830112611db957611db86119cc565b5b8135611dc9848260208601611d3b565b91505092915050565b60008060408385031215611de957611de8611964565b5b600083013567ffffffffffffffff811115611e0757611e06611969565b5b611e1385828601611da4565b925050602083013567ffffffffffffffff811115611e3457611e33611969565b5b611e4085828601611ae4565b9150509250929050565b60008060408385031215611e6157611e60611964565b5b600083013567ffffffffffffffff811115611e7f57611e7e611969565b5b611e8b85828601611ae4565b925050602083013567ffffffffffffffff811115611eac57611eab611969565b5b611eb885828601611ae4565b9150509250929050565b600060208284031215611ed857611ed7611964565b5b6000611ee6848285016119b7565b91505092915050565b600082825260208201905092915050565b7f536f75726365206d75737420626520746865206f7261636c65206f662074686560008201527f2072657175657374000000000000000000000000000000000000000000000000602082015250565b6000611f5c602883611eef565b9150611f6782611f00565b604082019050919050565b60006020820190508181036000830152611f8b81611f4f565b9050919050565b7f52657175657374206973206e6f742076616c6964000000000000000000000000600082015250565b6000611fc8601483611eef565b9150611fd382611f92565b602082019050919050565b60006020820190508181036000830152611ff781611fbb565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061206782611b6e565b915061207283611b6e565b925082820190508082111561208a5761208961202d565b5b92915050565b600061209b82611b6e565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036120cd576120cc61202d565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061211282611b6e565b915061211d83611b6e565b92508261212d5761212c6120d8565b5b828204905092915050565b7f496e76616c6964206f7261636c6520696e646578000000000000000000000000600082015250565b600061216e601483611eef565b915061217982612138565b602082019050919050565b6000602082019050818103600083015261219d81612161565b9050919050565b60007fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b6121d9816121a4565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b838110156122195780820151818401526020810190506121fe565b60008484015250505050565b6000612230826121df565b61223a81856121ea565b935061224a8185602086016121fb565b612253816119d6565b840191505092915050565b600061010082019050612274600083018b611c44565b612281602083018a611b78565b61228e6040830189611c9b565b61229b6060830188611c44565b6122a860808301876121d0565b6122b560a0830186611b78565b6122c260c0830185611b78565b81810360e08301526122d48184612225565b90509998505050505050505050565b6000819050919050565b60006122f8826122e3565b9150612303836122e3565b925082820390508181126000841216828213600085121516171561232a5761232961202d565b5b92915050565b6000819050919050565b600061235561235061234b8461196e565b612330565b61196e565b9050919050565b60006123678261233a565b9050919050565b60006123798261235c565b9050919050565b60008160601b9050919050565b600061239882612380565b9050919050565b60006123aa8261238d565b9050919050565b6123c26123bd8261236e565b61239f565b82525050565b6000819050919050565b6123e36123de82611b6e565b6123c8565b82525050565b60006123f582856123b1565b60148201915061240582846123d2565b6020820191508190509392505050565b600060608201905061242a6000830186611c44565b6124376020830185611b78565b81810360408301526124498184612225565b9050949350505050565b61245c81611caa565b811461246757600080fd5b50565b60008151905061247981612453565b92915050565b60006020828403121561249557612494611964565b5b60006124a38482850161246a565b91505092915050565b7f756e61626c6520746f207472616e73666572416e6443616c6c20746f206f726160008201527f636c650000000000000000000000000000000000000000000000000000000000602082015250565b6000612508602383611eef565b9150612513826124ac565b604082019050919050565b60006020820190508181036000830152612537816124fb565b9050919050565b600061254982611b6e565b915061255483611b6e565b925082612564576125636120d8565b5b828206905092915050565b600061257a82611b6e565b915061258583611b6e565b925082820390508181111561259d5761259c61202d565b5b92915050565b60006125ae82611b6e565b91506125b983611b6e565b92508282026125c781611b6e565b915082820484148315176125de576125dd61202d565b5b5092915050565b60008160011c9050919050565b6000808291508390505b600185111561263c578086048111156126185761261761202d565b5b60018516156126275780820291505b8081029050612635856125e5565b94506125fc565b94509492505050565b6000826126555760019050612711565b816126635760009050612711565b81600181146126795760028114612683576126b2565b6001915050612711565b60ff8411156126955761269461202d565b5b8360020a9150848211156126ac576126ab61202d565b5b50612711565b5060208310610133831016604e8410600b84101617156126e75782820a9050838111156126e2576126e161202d565b5b612711565b6126f484848460016125f2565b9250905081840481111561270b5761270a61202d565b5b81810290505b9392505050565b600061272382611b6e565b915061272e83611b6e565b925061275b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484612645565b90509291505056fea2646970667358221220f42236863ced51eec7a36c52c3a7204377b2f02c7f998dbb4f1f16a92f5360ce64736f6c63430008190033
"""