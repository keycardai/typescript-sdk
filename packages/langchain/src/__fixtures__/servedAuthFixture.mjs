/**
 * The auth module a served deployment points `langgraph.json` at.
 *
 * The server loads auth by importing a file and reading one export, so a test
 * that wants the server's own dispatch has to give it a file. The suite builds
 * the `Auth` object and parks it here for this module to hand over.
 */

export default globalThis.__keycardServedAuth;
