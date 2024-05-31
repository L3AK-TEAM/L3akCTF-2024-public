import fire

def check_flag(flag, guess, *args, **kwargs):
    if flag == guess:
        return f"Correct! {guess} is the flag!"
    else:
        return f"Incorrect, you guessed {guess}, but the flag is {flag}."

if __name__ == '__main__':
    fire.Fire(check_flag)
