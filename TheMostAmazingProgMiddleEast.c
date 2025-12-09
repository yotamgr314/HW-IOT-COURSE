#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ctype.h>
#include <string.h>

#define NFC_RESET_PIN 4
#define NFC_CHIP_SELECT_PIN 5

MFRC522 rfidModule(NFC_CHIP_SELECT_PIN, NFC_RESET_PIN);
MFRC522::MIFARE_Key authKey;

const byte DATA_SECTOR_BLOCKS[] = {4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24};
const size_t DATA_SECTOR_BLOCK_COUNT = sizeof(DATA_SECTOR_BLOCKS) / sizeof(DATA_SECTOR_BLOCKS[0]);
const size_t MAX_CONFIG_BYTES = DATA_SECTOR_BLOCK_COUNT * 16;
const size_t MIN_CONFIG_BYTES = 97;

const char *FILLER_PATTERN_TEXT = "RFID_PROFILE_FILLER::v2::chunk-XYZ-987654321-";

void printHexBuffer(byte *byteArray, byte arraySize);
bool isMifareClassicCompatible(MFRC522::PICC_Type cardType);
bool authenticateDataBlock(byte targetBlock);
bool readDataBlock(byte targetBlock, byte *destination16);
bool writeDataBlock(byte targetBlock, const byte *source16);
bool readConfigFromCard(String &configOut);
bool writeConfigToCard(const String &configIn);
bool locateNumericField(const String &configText, size_t &fieldStart, size_t &fieldEnd, long &numericValue);
String enforceConfigLength(String configText);
String createDefaultConfigTemplate(long counterValue);
String updateCounterInConfig(const String &configText, long &previousValue, long &newValue);
bool findFirstNumberInConfig(const String &configText, int searchFromIndex, size_t &fieldStart, size_t &fieldEnd, long &numericValue);
bool findLabeledNumberField(const String &configText, const char *labelKeyword, size_t &fieldStart, size_t &fieldEnd, long &numericValue);

void setup() 
{
    Serial.begin(115200);
    while (!Serial) {}

    SPI.begin();
    rfidModule.PCD_Init();

    for (byte i = 0; i < 6; i++) {
        authKey.keyByte[i] = 0xFF;
    }

    Serial.println(F(">> Scan an RFID tag to sync the on-card experiment profile."));
    Serial.println(F(">> This demo uses a 256-byte logical profile spread over 16 data blocks."));
}

void loop() {
    if (!rfidModule.PICC_IsNewCardPresent() || !rfidModule.PICC_ReadCardSerial()) {
        return;
    }

    Serial.print(F("Card fingerprint (UID):"));
    printHexBuffer(rfidModule.uid.uidByte, rfidModule.uid.size);
    Serial.println();

    MFRC522::PICC_Type detectedPiccType = rfidModule.PICC_GetType(rfidModule.uid.sak);
    Serial.print(F("Card technology: "));
    Serial.println(rfidModule.PICC_GetTypeName(detectedPiccType));

    if (!isMifareClassicCompatible(detectedPiccType)) {
        Serial.println(F("This tag is not a supported MIFARE Classic family member. Skipping it."));
        rfidModule.PICC_HaltA();
        rfidModule.PCD_StopCrypto1();
        return;
    }

    String currentProfileConfig;
    if (!readConfigFromCard(currentProfileConfig)) {
        Serial.println(F("Could not load profile bytes from the tag."));
        rfidModule.PICC_HaltA();
        rfidModule.PCD_StopCrypto1();
        return;
    }

    Serial.print(F("Raw profile payload ("));
    Serial.print(currentProfileConfig.length());
    Serial.println(F(" chars):"));
    Serial.println(currentProfileConfig);

    long storedCounterBefore = 0;
    long storedCounterAfter = 0;
    String refreshedProfileConfig = updateCounterInConfig(currentProfileConfig, storedCounterBefore, storedCounterAfter);

    Serial.print(F("Previous counter snapshot: "));
    Serial.println(storedCounterBefore);
    Serial.print(F("Updated counter snapshot: "));
    Serial.println(storedCounterAfter);

    if (!writeConfigToCard(refreshedProfileConfig)) {
        Serial.println(F("Tag write operation for refreshed profile failed."));
        rfidModule.PICC_HaltA();
        rfidModule.PCD_StopCrypto1();
        return;
    }

    Serial.print(F("Final profile payload ("));
    Serial.print(refreshedProfileConfig.length());
    Serial.println(F(" chars) saved on tag:"));
    Serial.println(refreshedProfileConfig);

    rfidModule.PICC_HaltA();
    rfidModule.PCD_StopCrypto1();
}

bool isMifareClassicCompatible(MFRC522::PICC_Type cardType) {
    return cardType == MFRC522::PICC_TYPE_MIFARE_MINI ||
           cardType == MFRC522::PICC_TYPE_MIFARE_1K ||
           cardType == MFRC522::PICC_TYPE_MIFARE_4K;
}

bool authenticateDataBlock(byte targetBlock) {
    byte sectorTrailerBlock = (targetBlock / 4) * 4 + 3;
    MFRC522::StatusCode authStatus = (MFRC522::StatusCode)rfidModule.PCD_Authenticate(
        MFRC522::PICC_CMD_MF_AUTH_KEY_A, sectorTrailerBlock, &authKey, &(rfidModule.uid));

    if (authStatus != MFRC522::STATUS_OK) {
        Serial.print(F("AUTH failure on block "));
        Serial.print(targetBlock);
        Serial.print(F(": "));
        Serial.println(rfidModule.GetStatusCodeName(authStatus));
        return false;
    }
    return true;
}

bool readDataBlock(byte targetBlock, byte *destination16) {
    if (!authenticateDataBlock(targetBlock)) {
        return false;
    }

    byte readBuffer[18];
    byte bufferSize = sizeof(readBuffer);

    MFRC522::StatusCode readStatus = (MFRC522::StatusCode)rfidModule.MIFARE_Read(targetBlock, readBuffer, &bufferSize);
    if (readStatus != MFRC522::STATUS_OK) {
        Serial.print(F("READ failure when accessing block "));
        Serial.print(targetBlock);
        Serial.print(F(": "));
        Serial.println(rfidModule.GetStatusCodeName(readStatus));
        return false;
    }

    memcpy(destination16, readBuffer, 16);
    return true;
}

bool writeDataBlock(byte targetBlock, const byte *source16) {
    if (!authenticateDataBlock(targetBlock)) {
        return false;
    }

    MFRC522::StatusCode writeStatus = (MFRC522::StatusCode)rfidModule.MIFARE_Write(targetBlock, (byte *)source16, 16);
    if (writeStatus != MFRC522::STATUS_OK) {
        Serial.print(F("WRITE failure when updating block "));
        Serial.print(targetBlock);
        Serial.print(F(": "));
        Serial.println(rfidModule.GetStatusCodeName(writeStatus));
        return false;
    }

    return true;
}

bool readConfigFromCard(String &configOut) {
    char configBuffer[MAX_CONFIG_BYTES + 1];
    memset(configBuffer, 0, sizeof(configBuffer));

    byte singleBlockData[16];
    size_t writeOffset = 0;

    for (size_t blockIndex = 0; blockIndex < DATA_SECTOR_BLOCK_COUNT; ++blockIndex) {
        if (!readDataBlock(DATA_SECTOR_BLOCKS[blockIndex], singleBlockData)) {
            return false;
        }
        memcpy(configBuffer + writeOffset, singleBlockData, 16);
        writeOffset += 16;
    }

    configBuffer[MAX_CONFIG_BYTES] = '\0';
    configOut = String(configBuffer);
    return true;
}

bool writeConfigToCard(const String &configIn) {
    size_t totalBytesToWrite = configIn.length();
    if (totalBytesToWrite > MAX_CONFIG_BYTES) {
        totalBytesToWrite = MAX_CONFIG_BYTES;
    }

    byte singleBlockData[16];
    size_t readOffset = 0;

    for (size_t blockIndex = 0; blockIndex < DATA_SECTOR_BLOCK_COUNT; ++blockIndex) {
        memset(singleBlockData, 0, sizeof(singleBlockData));

        for (byte byteIndex = 0; byteIndex < 16; ++byteIndex) {
            size_t configIndex = readOffset + byteIndex;
            if (configIndex < totalBytesToWrite) {
                singleBlockData[byteIndex] = static_cast<byte>(configIn.charAt(configIndex));
            } else {
                singleBlockData[byteIndex] = 0;
            }
        }

        if (!writeDataBlock(DATA_SECTOR_BLOCKS[blockIndex], singleBlockData)) {
            return false;
        }

        readOffset += 16;
    }

    return true;
}

String enforceConfigLength(String configText) {
    if (configText.length() < MIN_CONFIG_BYTES) {
        configText += " [auto-fill v2] ";
        while (configText.length() < MIN_CONFIG_BYTES) {
            configText += FILLER_PATTERN_TEXT;
        }
    }

    if (configText.length() > MAX_CONFIG_BYTES) {
        configText.remove(MAX_CONFIG_BYTES);
    }

    return configText;
}

String createDefaultConfigTemplate(long counterValue) {
    String defaultConfig = "RFID lab profile: logical_counter = ";
    defaultConfig += counterValue;
    defaultConfig += " . Remaining space is filled with structured placeholder bytes for this experiment. ";
    defaultConfig += FILLER_PATTERN_TEXT;
    defaultConfig += " Extra filler segments keep the profile length constant across cards.";
    return enforceConfigLength(defaultConfig);
}

bool findFirstNumberInConfig(const String &configText, int searchFromIndex, size_t &fieldStart, size_t &fieldEnd, long &numericValue) {
    const int configLength = configText.length();

    if (searchFromIndex < 0) {
        searchFromIndex = 0;
    }

    for (int i = searchFromIndex; i < configLength; ++i) {
        char currentChar = configText.charAt(i);
        bool hasSign = (currentChar == '-' || currentChar == '+');

        if (isDigit(currentChar) || (hasSign && (i + 1 < configLength) && isDigit(configText.charAt(i + 1)))) {
            bool isNegative = (currentChar == '-');
            fieldStart = i;
            long parsedValue = 0;
            int j = i + (hasSign ? 1 : 0);

            while (j < configLength && isDigit(configText.charAt(j))) {
                parsedValue = parsedValue * 10 + (configText.charAt(j) - '0');
                ++j;
            }

            fieldEnd = j;
            numericValue = isNegative ? -parsedValue : parsedValue;
            return true;
        }
    }

    return false;
}

bool findLabeledNumberField(const String &configText, const char *labelKeyword, size_t &fieldStart, size_t &fieldEnd, long &numericValue) {
    int labelIndex = configText.indexOf(labelKeyword);
    if (labelIndex < 0) {
        return false;
    }

    int colonIndex = configText.indexOf(':', labelIndex);
    int numericSearchStart = (colonIndex >= 0) ? (colonIndex + 1) : (labelIndex + (int)strlen(labelKeyword));

    return findFirstNumberInConfig(configText, numericSearchStart, fieldStart, fieldEnd, numericValue);
}

bool locateNumericField(const String &configText, size_t &fieldStart, size_t &fieldEnd, long &numericValue) {
    if (findLabeledNumberField(configText, "balance", fieldStart, fieldEnd, numericValue)) {
        return true;
    }
    if (findLabeledNumberField(configText, "counter", fieldStart, fieldEnd, numericValue)) {
        return true;
    }
    return findFirstNumberInConfig(configText, 0, fieldStart, fieldEnd, numericValue);
}

String updateCounterInConfig(const String &configText, long &previousValue, long &newValue) {
    size_t numericStart = 0;
    size_t numericEnd = 0;
    long foundValue = 0;

    String workingConfig = configText;

    if (!locateNumericField(workingConfig, numericStart, numericEnd, foundValue)) {
        workingConfig = createDefaultConfigTemplate(5);
        if (!locateNumericField(workingConfig, numericStart, numericEnd, foundValue)) {
            previousValue = 5;
            newValue = 5;
            return workingConfig;
        }
    }

    previousValue = foundValue;
    newValue = foundValue - 1;
    if (newValue < 0) {
        newValue = 99;
    }

    String leftSegment = workingConfig.substring(0, static_cast<int>(numericStart));
    String rightSegment = workingConfig.substring(static_cast<int>(numericEnd));
    workingConfig = leftSegment + String(newValue) + rightSegment;

    return enforceConfigLength(workingConfig);
}

void printHexBuffer(byte *byteArray, byte arraySize) {
    for (byte i = 0; i < arraySize; i++) {
        Serial.print(byteArray[i] < 0x10 ? " 0" : " ");
        Serial.print(byteArray[i], HEX);
    }
}
