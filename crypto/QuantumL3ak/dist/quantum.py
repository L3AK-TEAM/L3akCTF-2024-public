import os
import random
import json

from collections import namedtuple
from typing import Dict
from qiskit import QuantumCircuit
from qiskit_aer import StatevectorSimulator
from qiskit_aer.backends.compatibility import Statevector
from random import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from enum import Enum

API_CHOICE = Enum("API_CHOICE", ["UploadCircuit", "DisplayCircuit", "PerformMeasurement", "Exit"])
API = namedtuple("API", ["ShortDesc", "Action"])
API_MAX_REQUEST = 3200
API_MENU : Dict[str, API] = {}

def build_api_menu(rng, statesim : StatevectorSimulator):
    global API_MENU
    API_MENU = {
        API_CHOICE.UploadCircuit: API(
            ShortDesc="Upload a circuit",
            Action=upload_circuit
        ),
        API_CHOICE.DisplayCircuit: API(
            ShortDesc="Display the uploaded circuit",
            Action=display_circuit
        ),
        API_CHOICE.PerformMeasurement: API(
            ShortDesc="Perform a measurement",
            Action=lambda: perform_measurement(rng, statesim)
        ),
        API_CHOICE.Exit: API(
            ShortDesc="Exit",
            Action=None
        )
    }

noise_circuit : QuantumCircuit = None
uploaded_circuit : QuantumCircuit = None
outcomes = []

def generate_noise():
    circuit = QuantumCircuit(8)
    controls = random.sample(range(8), k = 4)
    dependents = set(range(8)) - set(controls)
    for c in controls:
        circuit.h(c)
        coupled = random.sample(list(dependents), k=1)
        dependents -= set(coupled)
        for cx in coupled:
            circuit.cx(c, cx)
    return circuit

def setup(rng):
    global noise_circuit
    noise_circuit = generate_noise()
    build_api_menu(rng, StatevectorSimulator())

def display_menu(api_requests):
    print("You may:")
    for i, (_, api) in enumerate(API_MENU.items(), 1):
        print(f"{i}. {api.ShortDesc}")
    print(f"You have made {api_requests}/{API_MAX_REQUEST} requests")

def print_encrypted_flag(rng : Random):
    key = rng.getrandbits(128).to_bytes(16, byteorder='little')
    iv  = rng.getrandbits(128).to_bytes(16, byteorder='little')
    aes = AES.new(key, mode=AES.MODE_CBC, iv=iv)
    with open("./flag.txt", "rb") as flagfile:
        flag = pad(flagfile.read(), 16)
    ciphertext : bytes = aes.encrypt(flag)
    print("Flag:")
    print("ct:", ciphertext.hex())
    print("iv:", iv.hex())

def display_circuit():
    if uploaded_circuit is not None:
        print(uploaded_circuit.draw())
    else:
        print("No circuit has been uploaded")

def upload_circuit():
    global uploaded_circuit
    try:
        result = json.loads(input("Enter circuit json:"))
    except Exception:
        print("invalid json")
        return

    circuit = QuantumCircuit(8)
    try:
        for gate in result["gates"]:
            parse = gate.split(" ")
            if parse[0] == "H":
                which = int(parse[1])
                circuit.h(which)
            elif parse[0] == "CX":
                controller, controlled = int(parse[1]), int(parse[2])
                circuit.cx(controller, controlled)
    except Exception as e:
        print("Input is invalid.")
        print("Expected input is of the form:")
        print('{"gates": ["H 0", "CX 0 1", "H 3"]}')
        return
    print("Circuit has been uploaded")
    print(circuit.draw())
    uploaded_circuit = circuit

def perform_measurement(rng : Random, statesim : StatevectorSimulator):
    circuit = QuantumCircuit(8)
    noise = noise_circuit.copy()
    circuit = circuit.compose(noise)
    if uploaded_circuit is not None:
        circuit = circuit.compose(uploaded_circuit)
    result = statesim.run(circuit).result()
    statevector : Statevector = result.get_statevector()
    probs_dict = statevector.probabilities_dict()
    states = []
    probs = []
    state_count = len(probs_dict)
    for state in sorted(probs_dict.keys()):
        states.append(state)
        probs.append(round(probs_dict[state]*state_count))
    print(rng.choices(states, weights=probs)[0])

def main():
    api_requests = 0
    rng = Random(os.urandom(8))

    setup(rng)
    while True:
        if api_requests == API_MAX_REQUEST:
            break
        display_menu(api_requests)
        try:
            user = input("Choice: ")
            choice = API_CHOICE(int(user))
        except Exception as e:
            print("Invalid Choice", e)
        if choice not in API_MENU:
            print("Invalid Choice")
        elif choice == API_CHOICE.Exit:
            break
        else:
            API_MENU[choice].Action()
            api_requests += 1
        print("")
    print_encrypted_flag(rng)

if __name__ == "__main__":
    main()
