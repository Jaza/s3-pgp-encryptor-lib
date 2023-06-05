import { pgpEncryptS3Object } from "./src/core";
import { logger } from "./src/logging";
import { config } from "./src/config";

const run = async () => {
  if (process.argv.length < 5) {
    logger.error(
      "Usage: npm run encrypt-it " +
        "s3-region-goes-here s3-bucket-name-goes-here s3-object-key-goes-here"
    );
    return;
  }

  try {
    await pgpEncryptS3Object(
      process.argv[2],
      process.argv[3],
      process.argv[4],
      config,
      logger
    );
  } catch (err) {
    logger.error(err, { err });
    return;
  }
};

run();
