import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { sdkStreamMixin } from "@aws-sdk/util-stream-node";
import { mockClient } from "aws-sdk-client-mock";
import "aws-sdk-client-mock-jest";

import { pgpEncryptS3Object } from "../src/core";
import { logger } from "../src/logging";
import { Readable } from "stream";
import { Config } from "../src/config";
import { decrypt, decryptKey, readMessage, readPrivateKey } from "openpgp";

const MOCK_PGP_PUBLIC_KEY =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
  "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\n" +
  "1kkE7ZrJ+6QqpcnR7EtF1HQqkg==\n=7DHI\n" +
  "-----END PGP PUBLIC KEY BLOCK-----";

const MOCK_PGP_PRIVATE_KEY =
  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" +
  "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\n=QgAN\n" +
  "-----END PGP PRIVATE KEY BLOCK-----";

const MOCK_PGP_PASSPHRASE = "foobar123";

describe("core", () => {
  it("pgpEncryptS3Object should encrypt using key from config", async () => {
    const mockS3Client = mockClient(S3Client);
    const unencryptedData = new Uint8Array([42, 43, 44]);
    mockS3Client.on(GetObjectCommand).resolves({
      Body: sdkStreamMixin(Readable.from([unencryptedData])),
    });
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: MOCK_PGP_PUBLIC_KEY,
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };
    const s3BucketName = "bucket-foo";
    const s3ObjectKey = "object-foo.csv";

    await pgpEncryptS3Object(
      "region-foo",
      s3BucketName,
      s3ObjectKey,
      config,
      logger
    );

    expect(mockS3Client).toHaveReceivedCommandWith(GetObjectCommand, {
      Bucket: s3BucketName,
      Key: s3ObjectKey,
    });

    const putObjectCommandCall = mockS3Client.commandCalls(PutObjectCommand)[0];
    const encryptedData = new Uint8Array(
      putObjectCommandCall.firstArg.input.Body
    );

    const privateKey = await decryptKey({
      privateKey: await readPrivateKey({ armoredKey: MOCK_PGP_PRIVATE_KEY }),
      passphrase: MOCK_PGP_PASSPHRASE,
    });

    const { data: decryptedData } = await decrypt({
      message: await readMessage({ binaryMessage: encryptedData }),
      decryptionKeys: privateKey,
      format: "binary",
    });

    expect(decryptedData).toEqual(unencryptedData);

    expect(mockS3Client).toHaveReceivedCommandWith(DeleteObjectCommand, {
      Bucket: s3BucketName,
      Key: s3ObjectKey,
    });
  });

  it("pgpEncryptS3Object should encrypt using key from Secrets Manager", async () => {
    const mockS3Client = mockClient(S3Client);
    const mockSecretsManagerClient = mockClient(SecretsManagerClient);
    const unencryptedData = new Uint8Array([43, 44, 45]);
    mockS3Client.on(GetObjectCommand).resolves({
      Body: sdkStreamMixin(Readable.from([unencryptedData])),
    });
    mockSecretsManagerClient.on(GetSecretValueCommand).resolves({
      SecretString: `{"supersecretkey": ${JSON.stringify(
        MOCK_PGP_PUBLIC_KEY
      )}}`,
    });
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: "",
      secretsManagerRegion: "region-far",
      secretsManagerSecretId: "supersecretid",
      secretsManagerSecretKey: "supersecretkey",
    };
    const s3BucketName = "bucket-bar";
    const s3ObjectKey = "object-bar.csv";

    await pgpEncryptS3Object(
      "region-bar",
      s3BucketName,
      s3ObjectKey,
      config,
      logger
    );

    expect(mockS3Client).toHaveReceivedCommandWith(GetObjectCommand, {
      Bucket: s3BucketName,
      Key: s3ObjectKey,
    });

    const putObjectCommandCall = mockS3Client.commandCalls(PutObjectCommand)[0];
    const encryptedData = new Uint8Array(
      putObjectCommandCall.firstArg.input.Body
    );

    const privateKey = await decryptKey({
      privateKey: await readPrivateKey({ armoredKey: MOCK_PGP_PRIVATE_KEY }),
      passphrase: MOCK_PGP_PASSPHRASE,
    });

    const { data: decryptedData } = await decrypt({
      message: await readMessage({ binaryMessage: encryptedData }),
      decryptionKeys: privateKey,
      format: "binary",
    });

    expect(decryptedData).toEqual(unencryptedData);

    expect(mockS3Client).toHaveReceivedCommandWith(DeleteObjectCommand, {
      Bucket: s3BucketName,
      Key: s3ObjectKey,
    });
  });

  it("pgpEncryptS3Object should error when missing s3ObjectKey", async () => {
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: MOCK_PGP_PUBLIC_KEY,
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };

    await expect(
      pgpEncryptS3Object("region-foo", "bucket-foo", "", config, logger)
    ).rejects.toThrow("Missing s3ObjectKey");
  });

  it("pgpEncryptS3Object should error when missing s3Region", async () => {
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: MOCK_PGP_PUBLIC_KEY,
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };

    await expect(
      pgpEncryptS3Object("", "bucket-foo", "object-foo.csv", config, logger)
    ).rejects.toThrow("Missing s3Region");
  });

  it("pgpEncryptS3Object should error when missing s3BucketName", async () => {
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: MOCK_PGP_PUBLIC_KEY,
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };

    await expect(
      pgpEncryptS3Object("region-foo", "", "object-foo.csv", config, logger)
    ).rejects.toThrow("Missing s3BucketName");
  });

  it("pgpEncryptS3Object should error when missing PGP public key", async () => {
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: "",
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };

    await expect(
      pgpEncryptS3Object(
        "region-foo",
        "bucket-foo",
        "object-foo.csv",
        config,
        logger
      )
    ).rejects.toThrow(
      "Missing either pgpPublicKey or " +
        "(secretsManagerRegion and secretsManagerSecretId and secretsManagerSecretKey)"
    );
  });

  it("pgpEncryptS3Object should do nothing when s3Object has .pgp", async () => {
    const config: Config = {
      debugLogging: false,
      pgpPublicKey: MOCK_PGP_PUBLIC_KEY,
      secretsManagerRegion: "",
      secretsManagerSecretId: "",
      secretsManagerSecretKey: "",
    };

    expect(
      await pgpEncryptS3Object(
        "region-foo",
        "bucket-foo",
        "object-foo.csv.pgp",
        config,
        logger
      )
    ).toBeFalsy();
  });
});
