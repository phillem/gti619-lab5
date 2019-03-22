class security_parameters():
    failedAttemptsMax = 5
    pwCapitalAmount = 0
    pwNumberAmount = 0
    pwSpecialCharacterAmount = 0

    def __init__(self):
        self.passwordMin = 8
        self.passwordMax = 8000
        self.usernameMin = 4
        self.usernameMax = 1500

