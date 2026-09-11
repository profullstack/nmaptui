/** Process entry: run the CLI with the real argv. */
import { main } from "./cli.ts";

main(process.argv.slice(2)).catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
