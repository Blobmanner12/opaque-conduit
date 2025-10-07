import fs from 'fs';
import path from 'path';

export default function handler(req, res) {
  try {
    // Construct the absolute path to the 'stage2_loader.lua' file.
    // '__dirname' points to the current directory ('/api/'). We need to go up
    // two levels to the project root, then into the 'client' directory.
    const filePath = path.join(process.cwd(), 'client', 'stage2_loader.lua');

    // Read the file's contents synchronously.
    // The 'utf8' encoding is specified to get a string, not a buffer.
    const stage2LoaderScript = fs.readFileSync(filePath, 'utf8');

    // Serve the content of the file.
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(stage2LoaderScript);
  } catch (error) {
    // If the file cannot be read for any reason (e.g., not found, permissions error),
    // log the error on the server and send a clear 500 error to the client.
    // This provides a much clearer debugging signal than FUNCTION_INVOCATION_FAILED.
    console.error("FATAL: Could not read 'client/stage2_loader.lua'.", error);
    res.status(500).json({ 
      error: "Internal Server Error", 
      message: "The Stage 2 client loader could not be accessed." 
    });
  }
}