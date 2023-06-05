import { config } from "./config";
import { createLogger, transports, format } from "winston";

const myFormat = format.printf((info) => {
  return (
    `${info.timestamp} ${info.level}: ${info.message}` +
    `${info.stack ? info.stack.replace(/^[^\n]+/, "") : ""}`
  );
});

const logger = createLogger({
  level: config.debugLogging ? "debug" : "info",
  transports: [
    new transports.Console({
      format: format.combine(
        format.errors({ stack: true }),
        format.colorize(),
        format.timestamp(),
        myFormat
      ),
    }),
  ],
});

export { logger };
