import { bundle } from "https://deno.land/x/emit/mod.ts";

const result = await bundle('main.ts');
console.log(result)
await Deno.writeTextFile('main.bundle.js', result.code);

// Get the file name from the command line argument
const fileName = 'main.bundle.js';

// Read the file content as a string
const fileContent = await Deno.readTextFile(fileName);

// Split the file content by line breaks
const lines = fileContent.split("\n");

// Filter out the lines that contain console.log
const filteredLines = lines.filter((line) => !line.includes("console.log"));

// Join the filtered lines by an empty string to remove line breaks
const newContent = filteredLines.join("");

// Write the new content to the same file
await Deno.writeTextFile(fileName, newContent);
