import socket
import random

grid_size = 1000000
tolerance = .01 * grid_size # allow for error of guess
num_games = 10  # Number of games
rounds_per_game = 100  # Rounds per game


def create_hidden_point(grid_size, margin):
    #Margin to ensure doesnt spawn on edge
    return (random.randint(margin, grid_size-margin), random.randint(margin, grid_size-margin))

def check_in_square(center, radius, point):
    x_min = center[0] - radius
    x_max = center[0] + radius
    y_min = center[1] - radius
    y_max = center[1] + radius
    return x_min <= point[0] <= x_max and y_min <= point[1] <= y_max

def handle_client():
    try:
        print(
            f"""Welcome to the Point Locator Challenge!

The object of this game is to find the coordinates of a hidden point on the grid.
Each round you will be given a new random point on the grid and you will give us a radius of a square.
We will return if the hidden point was in the area of your square.
After {rounds_per_game} rounds you will be asked to submit your guess of the coordinates of the hidden point x,y.
To win you will have to win 10 games in a row.

The size of your grid is {grid_size}, {grid_size}

You have an error of {tolerance}

"""
            )



        print(f"Number of games you must win: {num_games}\nNumber of rounds per game: {rounds_per_game}\n\n") 

        for game in range(1, num_games + 1):
            margin = int(grid_size * 0.2)  # 20% margin on each side
            hidden_point = create_hidden_point(grid_size, margin)
            print(f"***Game: {game}***\n")


            for round in range(1, rounds_per_game + 1):
                random_point = (random.randint(0, grid_size), random.randint(0, grid_size))
                print(f"Round {round}: Point is {random_point}\nEnter Radius Length> ")

                try:
                    radius = int(input().strip())
                except:
                    break
                    print("Wrong Format\n\n")
                    return
                in_square = check_in_square(random_point, radius, hidden_point)

                if in_square:
                    print(f"\033[94mThe hidden point is inside your square!\033[0m\n\n")
                else:
                    print(f"The hidden point is outside your square.\n\n")

            # After all rounds, ask for the player's guess
            print("Guess the hidden point (format 'x,y'): ")
            player_guess = input().strip()
            try:
                guess_x, guess_y = map(int, player_guess.split(','))
            except:
                guess_x, guess_y = -1,-1
                print("Wrong Format\n\n")
                return
            
            # tolerance give some room for error
            if (hidden_point[0] - tolerance <= guess_x <= hidden_point[0] + tolerance) and (hidden_point[1] - tolerance <= guess_y <= hidden_point[1] + tolerance):
                print("\033[92mCorrect! You've found the hidden point.\033[0m\n\n")
            else:
                print(f"\033[91mIncorrect. The actual hidden point was {hidden_point}.\033[0m\n")

                print("Game over. Thanks for playing!\n")
                return
        from secret import FLAG
        final_flag = (f'\033[95mCongratulations, you\'ve done it. Here is your flag: {FLAG}\033[0m\n')
        print(final_flag)
        return
    except Error:
        pass
    finally:
        return

if __name__ == "__main__":
    handle_client()
