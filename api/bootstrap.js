import fs from 'fs';
import path from 'path';

export default function handler(req, res) {
  try {
    const filePath = path.join(process.cwd(), 'client', 'stage2_loader.lua');
    const stage2LoaderScript = fs.readFileSync(filePath, 'utf8');

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(stage2LoaderScript);
  } catch (error) {
    console.error("FATAL: Could not read 'client/stage2_loader.lua'.", error);
    res.status(500).json({ 
      error: "Internal Server Error", 
      message: "The Stage 2 client loader could not be accessed." 
    });
  }
}