# main.py

from blp_model import BLPModel


def init_system():
    print("[System] Initializing Default State...")

    blp = BLPModel()

    # Subjects
    blp.add_subject("alice", "S", "U")
    blp.add_subject("bob", "C", "C")
    blp.add_subject("eve", "U", "U")

    # Objects
    blp.add_object("pub.txt", "U")
    blp.add_object("emails.txt", "C")
    blp.add_object("username.txt", "S")
    blp.add_object("password.txt", "TS")

    return blp


def run_case(case):
    print(f"\n================ CASE #{case} ================\n")

    blp = init_system()

    if case == 1:
        blp.read("alice", "emails.txt")

    elif case == 2:
        blp.read("alice", "password.txt")

    elif case == 3:
        blp.read("eve", "pub.txt")

    elif case == 4:
        blp.read("eve", "emails.txt")

    elif case == 5:
        blp.read("bob", "password.txt")

    elif case == 6:
        blp.read("alice", "emails.txt")
        blp.write("alice", "pub.txt")

    elif case == 7:
        blp.read("alice", "emails.txt")
        blp.write("alice", "password.txt")

    elif case == 8:
        blp.read("alice", "emails.txt")
        blp.write("alice", "emails.txt")
        blp.read("alice", "username.txt")
        blp.write("alice", "emails.txt")

    elif case == 9:
        blp.read("alice", "username.txt")
        blp.write("alice", "emails.txt")
        blp.read("alice", "password.txt")
        blp.write("alice", "password.txt")

    elif case == 10:
        blp.read("alice", "pub.txt")
        blp.write("alice", "emails.txt")
        blp.read("bob", "emails.txt")

    elif case == 11:
        blp.read("alice", "pub.txt")
        blp.write("alice", "username.txt")
        blp.read("bob", "username.txt")

    elif case == 12:
        blp.read("alice", "pub.txt")
        blp.write("alice", "password.txt")
        blp.read("bob", "password.txt")

    elif case == 13:
        blp.read("alice", "pub.txt")
        blp.write("alice", "emails.txt")
        blp.read("eve", "emails.txt")

    elif case == 14:
        blp.read("alice", "emails.txt")
        blp.write("alice", "pub.txt")
        blp.read("eve", "pub.txt")

    elif case == 15:
        blp.set_level("alice", "S")
        blp.read("alice", "username.txt")

    elif case == 16:
        blp.read("alice", "emails.txt")
        blp.set_level("alice", "U")
        blp.write("alice", "pub.txt")
        blp.read("eve", "pub.txt")

    elif case == 17:
        blp.read("alice", "username.txt")
        blp.set_level("alice", "C")
        blp.write("alice", "emails.txt")
        blp.read("eve", "emails.txt")

    elif case == 18:
        blp.read("eve", "pub.txt")
        blp.read("eve", "emails.txt")

    blp.show_state()


def menu():

    print("=========================================")
    print(" Bell-LaPadula (BLP) Simulator CLI")
    print("=========================================\n")

    while True:
        print("Options:")
        print("[1-18] Run a specific test case (1 to 18)")
        print("[A] Run all test cases sequentially")
        print("[Q] Quit\n")

        choice = input("Enter choice: ").strip().lower()

        if choice == "q":
            break

        elif choice == "a":
            for i in range(1, 19):
                run_case(i)

        elif choice.isdigit() and 1 <= int(choice) <= 18:
            run_case(int(choice))

        else:
            print("Invalid choice\n")


if __name__ == "__main__":
    menu()