def print_colored(text, color_name):
    """Print text in specified color."""
    color_codes = {
        'black': '30', 'red': '31', 'green': '32', 'yellow': '33',
        'blue': '34', 'magenta': '35', 'cyan': '36', 'white': '37',
        'bright_black': '90', 'bright_red': '91', 'bright_green': '92',
        'bright_yellow': '93', 'bright_blue': '94', 'bright_magenta': '95',
        'bright_cyan': '96', 'bright_white': '97',
    }
    color_code = color_codes.get(color_name.lower(), '37')  
    print(f"\033[{color_code}m{text}\033[0m")