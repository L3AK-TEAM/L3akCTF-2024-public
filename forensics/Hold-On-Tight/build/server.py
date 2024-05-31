import socket
import time

# Assuming you have a predefined list of mini flags
mini_flags = ['L3ak{rc_l0c4l_0n_b00t}', 'L3ak{53rv1c3_@nd_T1m3r}', 'L3ak{5h311_0f_7h3_D4y}', 'L3ak{Cr0n5_50_C71ch3}',
              'L3ak{5up3r_5h311_u53r}','L3ak{initd_2_b0075}', 'L3ak{10g_7h47_5h311}','L3ak{4p7_In57411_5h311}']
found_flags = []

def handle_client():
    try:
        welcome_message = (
            "Welcome to the ultra-realistic Flag Finder Simulation!\n"
            "A stealthy hacker has compromised this system and deployed 8 cunning persistence mechanisms.\n"
            "Your mission, should you choose to accept it, involves the /etc directory, a known haven for configuration treachery.\n"
            "Each mechanism is cleverly referencing /tmp/backdoor.sh – a nefarious script, no doubt.\n"
            "Alongside each persistence mechanism, a flag is concealed. Secure all 8 to halt the hacker’s scheme.\n"
            "Report back with each flag as you uncover them. Each mini flag has L3ak{} format.\n"
            "Remember: After securing the 8 mini flags, the ultimate flag shall unveil itself.\n"
            "Gear up, remain vigilant, and good luck!\n"
        )

        print(welcome_message)
        wrong_guesses = 0
        last_attempt_time = time.time()
        while len(found_flags) < len(mini_flags):
            # Enforce rate limit
            current_time = time.time()
            wait_time = 5 * (wrong_guesses // 3 ) if wrong_guesses > 3 else 0
            time_since_last_attempt = current_time - last_attempt_time

            
            
            # Send the current status of found flags
            status_message = f"Flags found: {len(found_flags)}/{len(mini_flags)}.\n\n"
            if found_flags:
                status_message += f"You have found:\033[95m {' '.join(found_flags)}\033[0m\n"
            if wait_time > 0 and time_since_last_attempt < wait_time:
                remaining_time = wait_time - time_since_last_attempt
                status_message += f"Rate limit enforced. Please wait {remaining_time:.2f} seconds.\n"
                print(status_message)
                input()  # Read any input which should be ignored
                continue
            else:
                status_message += "Submit a mini flag: "
                print(status_message)

            # Receive a mini flag from the player
            mini_flag = input().strip()

            # Check if the submitted flag is one of the mini flags and hasn't been found yet
            if mini_flag in mini_flags and mini_flag not in found_flags:
                found_flags.append(mini_flag)
                print("\033[92mCorrect! Mini flag accepted.\033[0m\n")
            elif mini_flag in found_flags:
                print("You have already submitted this mini flag.\n")
            else:
                wrong_guesses += 1
                last_attempt_time = time.time()
                print("\033[91mIncorrect flag. Try again.\033[0m\n")

        # All flags found, reveal the final flag
        from secret import FLAG
        print(f'\033[95mCongratulations, you\'ve done it. Here is your flag: {FLAG}\033[0m')
    except Error:
        pass

if __name__ == "__main__":
    handle_client()
