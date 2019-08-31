# OpenTok .Net Standard SDK
Implementation of the Tokbox OpenTok [REST api](https://tokbox.com/developer/rest/) and port of a few SDK methods, see https://github.com/opentok/Opentok-.NET-SDK
## Scope
This SDK only implements the CreateSession and GenerateToken methods.
## Usage
This SDK is created for usage with e.g. Azure Functions in mind
```cs
// generate session
string sessionId = await OpenTok.CreateSessionAsync(System.Environment.GetEnvironmentVariable("TOKBOX_SECRET"), 
                System.Environment.GetEnvironmentVariable("TOKBOX_APIKEY"));

// generate token
string apiKey = System.Environment.GetEnvironmentVariable("TOKBOX_APIKEY");
string secret = System.Environment.GetEnvironmentVariable("TOKBOX_SECRET");
string role = "publisher"; // "moderator";
string data = null; // see https://tokbox.com/developer/guides/create-token/ Connection data
double ttl =  24 * 60 * 60;
string token = OpenTok.GenerateToken(secret, apiKey, sessionId, role, data, ttl);
```