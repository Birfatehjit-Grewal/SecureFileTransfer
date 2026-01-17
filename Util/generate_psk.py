from Crypto.Random import get_random_bytes

def generate_psk():
    psk = get_random_bytes(16)
    try:
        with open("tmp/psk.txt","wb") as file:
            file.write(psk)
    except FileNotFoundError or FileExistsError:
        print("File not created")



if __name__ == "__main__":
    generate_psk()