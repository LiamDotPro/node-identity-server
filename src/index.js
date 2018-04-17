import hasherV3 from './IdentityServer3/HashPasswordv3';

const newHasher = new hasherV3();

/**
 * Given a password hashes it using the identity 3/4 server implementation.
 * @param password
 * @returns {Promise<*>}
 */
export async function hashPassword(password) {
    return await newHasher.hashPassword(password);
}

/**
 * Given a password and a hash verify's if they match using the identity server 3/4 implementation.
 * @param plainTextPassword
 * @param hash
 * @returns {Promise<boolean|*>}
 */
export async function verifyPassword(plainTextPassword, hash) {
    return await newHasher.verifyPassword(plainTextPassword, hash);
}
