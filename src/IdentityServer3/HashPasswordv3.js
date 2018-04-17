import crypto from 'crypto';
import util from 'util';

const pbkdf2Async = util.promisify(crypto.pbkdf2);

export default class HashPasswordv3 {
    constructor() {

    }

    async verifyPassword(password, hashedPassword) {

        let decodedBuffer = null;

        if (hashedPassword) {
            decodedBuffer = Buffer.from(hashedPassword, 'base64');
        }

        let iteration = 10000;
        let key = decodedBuffer[0];
        let saltLength = this.readNetworkByteOrder(decodedBuffer, 9);

        if (saltLength < 128 / 8) {
            return false;
        }

        let salt = await crypto.randomBytes(16);

        // take the salt from the stored hash in the database.
        // we effectively overwrite the bytes here from our random buffer.
        decodedBuffer.copy(salt, 0, 13, 13 + saltLength);

        let subkeyLength = decodedBuffer.length - 13 - saltLength;

        if (subkeyLength < 128 / 8) {
            return false;
        }

        let expectedSubkey = new Buffer(32);

        decodedBuffer.copy(expectedSubkey, 0, 13 + saltLength, 13 + saltLength + expectedSubkey.length);

        let acutalSubkey = await pbkdf2Async(password, salt, 10000, 32, 'sha256');

        return this.areBuffersEqual(acutalSubkey, expectedSubkey);

    }

    async hashPassword(password) {

        try {
            // Create a salt with cryptographically secure method.
            let salt = await crypto.randomBytes(16);

            let subkey = await pbkdf2Async(password, salt, 10000, 32, 'sha256');

            let outputBytes = new Buffer(13 + salt.length + subkey.length);

            // Write in the format marker
            outputBytes[0] = 0x01;

            // Write out the byte order
            this.writeNetworkByteOrder(outputBytes, 1, 1);
            this.writeNetworkByteOrder(outputBytes, 5, 10000);
            this.writeNetworkByteOrder(outputBytes, 9, salt.length);

            salt.copy(outputBytes, 13, 0, 16);
            subkey.copy(outputBytes, 13 + salt.length, 0, subkey.length);

            return outputBytes.toString('base64');

        } catch (e) {
            new Error(e);
        }

    }

    /**
     * Writes the appropriate bytes into available slots
     * @param buffer
     * @param offset
     * @param value
     */
    writeNetworkByteOrder(buffer, offset, value) {
        buffer[offset + 0] = value >> 0;
        buffer[offset + 1] = value >> 8;
        buffer[offset + 2] = value >> 16;
        buffer[offset + 3] = value >> 24;
    }

    /**
     * Reads the bytes back out using an offset.
     * @param buffer
     * @param offset
     * @returns {number}
     */
    readNetworkByteOrder(buffer, offset) {
        return ((buffer[offset + 0]) << 24)
            | ((buffer[offset + 1]) << 16)
            | ((buffer[offset + 2]) << 8)
            | ((buffer[offset + 3]));
    }

    areBuffersEqual(bufA, bufB) {
        let len = bufA.length;
        if (len !== bufB.length) {
            return false;
        }
        for (let i = 0; i < len; i++) {
            if (bufA.readUInt8(i) !== bufB.readUInt8(i)) {
                return false;
            }
        }
        return true;
    }

}
