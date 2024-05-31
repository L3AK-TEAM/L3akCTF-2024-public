from pwn import *
from sys import argv
# Setup the connection
host = argv[1]
port = int(argv[2])
conn = remote(host, port)

# Function to print out data received from the server and strip newlines for readability
def print_data(data):
    print(data.decode().replace(r'\n', '\n').strip())

# Function to parse the point from the server message
def parse_point(data):
    point_data = data.split('Point is ')[1].split(')')[0].replace('(', '').strip()
    return tuple(map(int, point_data.split(', ')))

# Function to calculate the radius based on your strategy

def calculate_radius(point, bounding_box):
    x, y = point
    # Calculate distances from the point to each edge of the bounding box
    distances = [
        abs(x - bounding_box['min_x']),  # Distance to left edge
        abs(bounding_box['max_x'] - x),  # Distance to right edge
        abs(y - bounding_box['min_y']),  # Distance to top edge
        abs(bounding_box['max_y'] - y)   # Distance to bottom edge
    ]

    # The radius should be at least as large as the largest of these distances
    # This ensures the square covers from the point to beyond the middle of the bounding box in all directions
    radius = distances.sort()
    radius = int((distances[3]+distances[2])//2)
    print(max(radius, 1))
    return max(radius, 1)


def your_guessing_logic_here(bounding_box):
    x = (bounding_box['max_x']+ bounding_box['min_x'])//2
    y = (bounding_box['max_y'] + bounding_box['min_y'])//2
    return x,y

def update_bounding_box(bounding_box, new_square):
    # Assuming new_square is a tuple (center_x, center_y, radius)
    center_x, center_y, radius = new_square
    min_x = center_x - radius
    max_x = center_x + radius
    min_y = center_y - radius
    max_y = center_y + radius
    
    # Update the bounding box with the intersection of the new square
    bounding_box['min_x'] = max(bounding_box['min_x'], min_x)
    bounding_box['max_x'] = min(bounding_box['max_x'], max_x)
    bounding_box['min_y'] = max(bounding_box['min_y'], min_y)
    bounding_box['max_y'] = min(bounding_box['max_y'], max_y)
    print(bounding_box)
    return bounding_box



def update_bounding_box_on_miss(point, radius, bounding_box):
    # Extract point coordinates
    x, y = point

    # Calculate boundaries of the square we just guessed and found a miss
    guessed_min_x = x - radius
    guessed_max_x = x + radius
    guessed_min_y = y - radius
    guessed_max_y = y + radius

    # Check each side to see if we can exclude areas beyond the guessed square
    # Only shrink the bounding box when we can definitively exclude areas based on the miss

    # Shrink from left if the guessed area covers the left edge of the bounding box
    if guessed_min_x <= bounding_box['min_x'] and guessed_max_x < bounding_box['max_x']:
        bounding_box['min_x'] = guessed_max_x

    # Shrink from right if the guessed area covers the right edge of the bounding box
    if guessed_max_x >= bounding_box['max_x'] and guessed_min_x > bounding_box['min_x']:
        bounding_box['max_x'] = guessed_min_x

    # Shrink from top if the guessed area covers the top edge of the bounding box
    if guessed_min_y <= bounding_box['min_y'] and guessed_max_y < bounding_box['max_y']:
        bounding_box['min_y'] = guessed_max_y

    # Shrink from bottom if the guessed area covers the bottom edge of the bounding box
    if guessed_max_y >= bounding_box['max_y'] and guessed_min_y > bounding_box['min_y']:
        bounding_box['max_y'] = guessed_min_y

    # Ensure the boundaries do not cross each other
    bounding_box['min_x'] = min(bounding_box['min_x'], bounding_box['max_x'])
    bounding_box['min_y'] = min(bounding_box['min_y'], bounding_box['max_y'])
    bounding_box['max_x'] = max(bounding_box['min_x'], bounding_box['max_x'])
    bounding_box['max_y'] = max(bounding_box['min_y'], bounding_box['max_y'])

    return bounding_box







# Function to handle the server's response
def handle_response(data,point,radius,bounding_box):
    print(data)  # You can process the server response here
    if 'inside' in data.lower():
        # If you found the point, adjust your strategy if needed
        bounding_box = update_bounding_box(bounding_box, (point[0], point[1], radius))
        print('yee',point)
    elif 'outside' in data.lower():
        # If the point is outside your square, adjust your strategy
        #bounding_box = update_bounding_box_on_miss(point, radius, bounding_box)
        print('naw fam')
    return bounding_box

def reset_box():
    bounding_box = {
        'min_x': 0,
        'max_x': 1000000,  # Assuming the grid size is 500x500
        'min_y': 0,
        'max_y': 1000000
    }
    return bounding_box

# Main function
def main():
    # Read the initial messages from the server
    initial_data = conn.recvuntil(b"The size of your grid is 1000000, 1000000")
    print_data(initial_data)
    c = 1
    # Initialize the bounding box with the maximum possible values.
    bounding_box = {
        'min_x': 0,
        'max_x': 1000000,  # Assuming the grid size is 500x500
        'min_y': 0,
        'max_y': 1000000
    }

    try:
        while True:
            data = conn.recvline(timeout=3).decode().strip()
            print(data)  # Print every line received from the server

            print(c)
            if 'Point is' in data:
                point = parse_point(data)
                if c < 5:
                    radius = 500000
                else:
                    radius = calculate_radius(point,bounding_box)
                print(f"Radius: {radius}")  # Print the radius we're sending
                conn.sendline(str(radius))  # Send the radius
                c+=1
                # Now read the server's response to see if you covered the point
                response = conn.recvline().decode().strip()
                bounding_box = handle_response(response,point,radius,bounding_box)
            elif c == 101:
                print(data)
                # If the server is prompting for a guess, handle it here
                guess = your_guessing_logic_here(bounding_box)
                print(guess,'GUESS')
                conn.sendline(f'{guess[0]},{guess[1]}')
                # Now read the server's response to see if you covered the point
                response = conn.recvline().decode().strip()
                bounding_box = reset_box()
                c = 1


    except EOFError:
        print("Connection closed by the server.")
    finally:
        conn.close()

if __name__ == '__main__':
    main()
