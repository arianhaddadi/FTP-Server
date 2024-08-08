import socket


def setupDataConnection(token):
    while True:
        dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dataSocket.connect(("localhost", 8001))

        dataSocket.send(token.encode())
        authenticationResponse = dataSocket.recv(2048).decode()

        if authenticationResponse == "OK":
            dataSocket.send("OK".encode())
            return dataSocket
        else:
            dataSocket.close()


def getFile(dataSocket, filename):
    dataResponse = dataSocket.recv(2500)
    if dataResponse != "No Data".encode():
        file = open(filename, "wb")
        file.write(dataResponse)
        dataSocket.send("OK".encode())
        while True:
            dataResponse = dataSocket.recv(2500)
            if dataResponse == "done".encode():
                dataSocket.close()
                file.close()
                break
            else:
                file.write(dataResponse)
                dataSocket.send("OK".encode())


def getList(dataSocket):
    data = ""
    while True:
        dataResponse = dataSocket.recv(2500).decode()
        if dataResponse != "done":
            data += dataResponse
            dataSocket.send("OK".encode())
        else:
            dataSocket.close()
            return data


def getData(loggedIn, commandSegments, token):
    data = "No Data"
    if loggedIn and (
        (len(commandSegments) == 1 and commandSegments[0] == "LIST")
        or (len(commandSegments) == 2 and commandSegments[0] == "DL")
    ):
        dataSocket = setupDataConnection(token)
        if commandSegments[0] == "LIST":
            data = getList(dataSocket)
        else:
            getFile(dataSocket, commandSegments[1])
    return data


if __name__ == "__main__":
    commandSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    commandSocket.connect(("localhost", 8000))
    token = commandSocket.recv(8).decode()

    loggedIn = False

    while True:
        command = input("Enter Your Command:")
        commandSocket.send(command.encode())

        commandSegments = command.split()
        data = getData(loggedIn, commandSegments, token)
        commandResponse = commandSocket.recv(2048).decode()
        print(commandResponse)
        if commandSegments[0] == "PASS" and commandResponse[:3] == "230":
            loggedIn = True

        if data != "No Data":
            print("\nData Response:")
            print(data)
