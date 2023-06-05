import { Readable } from "stream";

/**
 * Format bytes as human-readable text.
 *
 * Thanks to: https://stackoverflow.com/a/14919494
 *
 * @param bytes Number of bytes.
 *
 * @return Formatted string.
 */
const humanFileSize = (bytes: number) => {
  const thresh = 1024;

  if (Math.abs(bytes) < thresh) {
    return `${bytes}B`;
  }

  const units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
  let u = -1;
  const r = 1;

  do {
    bytes /= thresh;
    ++u;
  } while (
    Math.round(Math.abs(bytes) * r) / r >= thresh &&
    u < units.length - 1
  );

  return `${bytes.toFixed(0)}${units[u]}`;
};

/**
 * Convert a readable stream to a buffer.
 *
 * Thanks to: https://github.com/aws/aws-sdk-js-v3/issues/1877#issuecomment-1326311437
 *
 * @param stream Readable stream.
 *
 * @return Buffer that contains the stream data.
 */
const streamToBuffer = async (stream: Readable): Promise<Buffer> => {
  return await new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(Buffer.concat(chunks)));
  });
};

export { humanFileSize, streamToBuffer };
