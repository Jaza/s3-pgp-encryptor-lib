import dotenv from "dotenv";
import dotenvExpand from "dotenv-expand";

dotenvExpand.expand(dotenv.config({ path: ".env" }));

export interface Config {
  debugLogging: boolean;
  pgpPublicKey: string;
  secretsManagerRegion: string;
  secretsManagerSecretId: string;
  secretsManagerSecretKey: string;
}

const config: Config = {
  debugLogging: process.env.DEBUG_LOGGING === "1",
  pgpPublicKey: process.env.PGP_PUBLIC_KEY,
  secretsManagerRegion: process.env.SECRETS_MANAGER_REGION,
  secretsManagerSecretId: process.env.SECRETS_MANAGER_SECRET_ID,
  secretsManagerSecretKey: process.env.SECRETS_MANAGER_SECRET_KEY,
};

export { config };
