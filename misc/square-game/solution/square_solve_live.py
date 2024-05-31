from pwn import *

# Setup the connection
host = "34.139.98.117"
port = 6668
conn = remote(host, port)

# Function to print out data received from the server and strip newlines for readability
def print_data(data):
    print(data.decode().replace(r'\n', '\n').strip())

# Function to parse the point from the server message
def parse_point(data):
    point_data = data.split('Point is')[1].split(')')[0].replace('(', '').strip()
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
    distances.sort()
    radius = distances
    radius = int((distances[2]+distances[3])/2)
    return max(radius, distances[2]+1)


def your_guessing_logic_here(bounding_box):
    if not bounding_box:
        return 0,0
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
    
    if bounding_box == False:
        bounding_box = {
        'min_x': min_x,
        'max_x': max_x,
        'min_y': min_y,
        'max_y': max_y
        }
        return bounding_box

    # Update the bounding box with the intersection of the new square
    bounding_box['min_x'] = max(bounding_box['min_x'], min_x)
    bounding_box['max_x'] = min(bounding_box['max_x'], max_x)
    bounding_box['min_y'] = max(bounding_box['min_y'], min_y)
    bounding_box['max_y'] = min(bounding_box['max_y'], max_y)
    print('Current Bounding Box', bounding_box)
    return bounding_box



def update_bounding_box_on_miss(point, radius, bounding_box):
    if bounding_box == False:
        return False

    # Extract point coordinates
    x, y = point

    # Calculate boundaries of the guessed square
    guessed_min_x = x - radius
    guessed_max_x = x + radius
    guessed_min_y = y - radius
    guessed_max_y = y + radius

    # Check each side to determine if the guessed square edges are outside the bounding box
    # and adjust the bounding box edges only if the guessed square edge is within the bounding box.

    # Adjust left edge of the bounding box
    if bounding_box['min_x'] < guessed_max_x < bounding_box['max_x']:
        bounding_box['min_x'] = guessed_max_x
        return bounding_box

    # Adjust right edge of the bounding box
    if bounding_box['min_x'] < guessed_min_x < bounding_box['max_x']:
        bounding_box['max_x'] = guessed_min_x
        return bounding_box

    # Adjust top edge of the bounding box
    if bounding_box['min_y'] < guessed_max_y < bounding_box['max_y']:
        bounding_box['min_y'] = guessed_max_y
        return bounding_box

    # Adjust bottom edge of the bounding box
    if bounding_box['min_y'] < guessed_min_y < bounding_box['max_y']:
        bounding_box['max_y'] = guessed_min_y
        return bounding_box

    # Ensure the bounding box coordinates are not inverted
    if bounding_box['min_x'] > bounding_box['max_x']:
        bounding_box['min_x'], bounding_box['max_x'] = bounding_box['max_x'], bounding_box['min_x']
    if bounding_box['min_y'] > bounding_box['max_y']:
        bounding_box['min_y'], bounding_box['max_y'] = bounding_box['max_y'], bounding_box['min_y']

    return bounding_box




# Function to handle the server's response
def handle_response(data,point,radius,bounding_box):
    # You can process the server response here
    if 'inside' in data.lower():
        # If you found the point
        bounding_box = update_bounding_box(bounding_box, (point[0], point[1], radius))
    elif 'outside' in data.lower():
        # If the point is outside your square
        bounding_box = update_bounding_box_on_miss(point, radius, bounding_box)
    return bounding_box


# Main function
def main():
    # Read the initial messages from the server
    initial_data = conn.recvuntil(b"The size of your grid is 1000000, 1000000")
    print_data(initial_data)
    c = 1
    bounding_box = False
    try:
        while True:
            data = conn.recvline(timeout=3).decode().strip()
            print(data)  # Print every line received from the server
            response = ''
            if 'Point is' in data:
                point = parse_point(data)
                if bounding_box == False:
                    radius = 370000
                else:
                    radius = calculate_radius(point, bounding_box)
                print(f"Radius: {radius}")  # Print the radius we're sending
                conn.sendline(str(radius))  # Send the radius
                c += 1
            elif 'idden point is' in data:
                bounding_box = handle_response(data, point, radius, bounding_box)
                guess = your_guessing_logic_here(bounding_box)
                print(f"Current Guess: {guess}")  # Print the guess
            elif c >= 100 and 'Guess' in data:
                print(data)
                # If the server is prompting for a guess, handle it here
                guess = your_guessing_logic_here(bounding_box)
                print(f"Guess: {guess}")  # Print the guess
                conn.sendline(f'{guess[0]},{guess[1]}')
                bounding_box = False
                c = 1

    except EOFError:
        print("Connection closed by the server.")
    finally:
        conn.close()


if __name__ == '__main__':
    main()
              
