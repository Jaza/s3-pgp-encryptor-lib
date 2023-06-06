import { PassThrough, Readable } from "stream";
import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { Key, createMessage, encrypt, readKey } from "openpgp";

import { Logger } from "winston";
import { humanFileSize, streamToBuffer } from "./utils";
import { Config } from "./config";

/**
 * Validate the specified params before encrypting.
 */
const _validateBeforeEncrypt = (
  pgpPublicKeyFromConfig: string,
  secretsManagerRegion: string,
  secretsManagerSecretId: string,
  secretsManagerSecretKey: string,
  s3Region: string,
  s3BucketName: string,
  s3ObjectKey: string
) => {
  if (!s3ObjectKey) {
    throw new Error("Missing s3ObjectKey");
  }

  if (!s3Region) {
    throw new Error("Missing s3Region");
  }

  if (!s3BucketName) {
    throw new Error("Missing s3BucketName");
  }

  if (
    !pgpPublicKeyFromConfig &&
    !(secretsManagerRegion && secretsManagerSecretId && secretsManagerSecretKey)
  ) {
    throw new Error(
      "Missing either pgpPublicKey or " +
        "(secretsManagerRegion and secretsManagerSecretId and secretsManagerSecretKey)"
    );
  }
};

/**
 * Get the PGP public key either from local config or from Secrets Manager.
 */
const _getPublicKey = async (
  pgpPublicKeyFromConfig: string,
  secretsManagerRegion: string,
  secretsManagerSecretId: string,
  secretsManagerSecretKey: string,
  pgpPublicKeyLogMsg: string,
  logger: Logger
): Promise<Key> => {
  let pgpPublicKey: string;

  if (pgpPublicKeyFromConfig) {
    pgpPublicKey = pgpPublicKeyFromConfig;
  } else {
    const secretsManagerClient = new SecretsManagerClient({
      region: secretsManagerRegion,
    });
    const getSecretValueCommand = new GetSecretValueCommand({
      SecretId: secretsManagerSecretId,
    });

    const getSecretValueResp = await secretsManagerClient.send(
      getSecretValueCommand
    );
    pgpPublicKey = JSON.parse(getSecretValueResp.SecretString)[
      secretsManagerSecretKey
    ];
  }

  const publicKey = await readKey({ armoredKey: pgpPublicKey });

  logger.info(
    `Read public key of size ${humanFileSize(publicKey.armor().length)} from ` +
      `${pgpPublicKeyLogMsg}`
  );

  return publicKey;
};

/**
 * Get the specified S3 object.
 */
const _getUnencryptedData = async (
  s3Region: string,
  s3BucketName: string,
  s3ObjectKeySanitized: string,
  logger: Logger
): Promise<Readable> => {
  const s3Client = new S3Client({ region: s3Region });

  const getObjectCommand = new GetObjectCommand({
    Bucket: s3BucketName,
    Key: s3ObjectKeySanitized,
  });

  const getObjectResp = await s3Client.send(getObjectCommand);
  const unencryptedData = getObjectResp.Body as Readable;
  logger.info(`Read head of unencrypted data from ${s3ObjectKeySanitized}`);

  return unencryptedData;
};

/**
 * Save the specified S3 object.
 */
const _saveEncryptedData = async (
  s3Region: string,
  s3BucketName: string,
  s3ObjectKeyEncrypted: string,
  encryptedData: Readable,
  logger: Logger
) => {
  const s3Client = new S3Client({ region: s3Region });
  const passThrough = new PassThrough();
  encryptedData.pipe(passThrough);

  const s3Upload = new Upload({
    client: s3Client,
    params: {
      Bucket: s3BucketName,
      Key: s3ObjectKeyEncrypted,
      Body: passThrough,
    },
  });

  s3Upload.on("httpUploadProgress", (progress) => {
    logger.info(
      `Saving encrypted data to ${progress.Key}, ` +
        `loaded: ${
          progress.loaded ? humanFileSize(progress.loaded) : "unknown"
        }, ` +
        `total: ${progress.total ? humanFileSize(progress.total) : "unknown"}`
    );
  });

  await s3Upload.done();

  logger.info(`Saved encrypted data to ${s3ObjectKeyEncrypted}`);
};

/**
 * Delete the specified S3 object.
 */
const _deleteUnencryptedData = async (
  s3Region: string,
  s3BucketName: string,
  s3ObjectKeySanitized: string,
  logger: Logger
) => {
  const s3Client = new S3Client({ region: s3Region });

  const deleteObjectCommand = new DeleteObjectCommand({
    Bucket: s3BucketName,
    Key: s3ObjectKeySanitized,
  });

  await s3Client.send(deleteObjectCommand);

  logger.info(`Deleted source object ${s3ObjectKeySanitized}`);
};

/**
 * PGP encrypt the specified S3 object.
 */
const pgpEncryptS3Object = async (
  s3Region: string,
  s3BucketName: string,
  s3ObjectKey: string,
  config: Config,
  logger: Logger
): Promise<boolean> => {
  if (s3ObjectKey.endsWith(".pgp")) {
    logger.info(
      `Not encrypting ${s3ObjectKey} because it appears to already be encrypted`
    );
    return false;
  }

  const pgpPublicKeyFromConfig = config.pgpPublicKey;
  const secretsManagerRegion = config.secretsManagerRegion;
  const secretsManagerSecretId = config.secretsManagerSecretId;
  const secretsManagerSecretKey = config.secretsManagerSecretKey;

  _validateBeforeEncrypt(
    pgpPublicKeyFromConfig,
    secretsManagerRegion,
    secretsManagerSecretId,
    secretsManagerSecretKey,
    s3Region,
    s3BucketName,
    s3ObjectKey
  );

  const s3ObjectKeySanitized = s3ObjectKey
    .replace(/\+/g, " ")
    .replace(/%2B/g, "+");

  const s3ObjectKeyEncrypted = `${s3ObjectKeySanitized}.pgp`;

  const pgpPublicKeyLogMsg = pgpPublicKeyFromConfig
    ? "PGP_PUBLIC_KEY"
    : `${secretsManagerSecretId} / ${secretsManagerSecretKey}`;

  logger.info(
    `Encrypting source object ${s3ObjectKeySanitized} in S3 bucket ${s3BucketName} ` +
      `in region ${s3Region} to destination object ${s3ObjectKeyEncrypted} using PGP ` +
      `public key from ${pgpPublicKeyLogMsg}`
  );

  const publicKey = await _getPublicKey(
    pgpPublicKeyFromConfig,
    secretsManagerRegion,
    secretsManagerSecretId,
    secretsManagerSecretKey,
    pgpPublicKeyLogMsg,
    logger
  );

  const unencryptedData = await _getUnencryptedData(
    s3Region,
    s3BucketName,
    s3ObjectKeySanitized,
    logger
  );

  const encryptedData = (await encrypt({
    message: await createMessage({ binary: unencryptedData }),
    encryptionKeys: publicKey,
    format: "binary",
  })) as Readable;

  await _saveEncryptedData(
    s3Region,
    s3BucketName,
    s3ObjectKeyEncrypted,
    encryptedData,
    logger
  );

  await _deleteUnencryptedData(
    s3Region,
    s3BucketName,
    s3ObjectKeySanitized,
    logger
  );

  return true;
};

export { pgpEncryptS3Object };
