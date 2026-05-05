// FunSIP routing script
// This script is called for each out-of-dialog or dialog-initiating SIP request.
// In-dialog requests (with To-tag) are automatically routed by the proxy using
// Route headers per RFC3261 Section 16.

var DOMAIN = "localhost";

function onRequest(req) {

    // --- REGISTER ---
    if (req.method === "REGISTER") {
        if (!authenticate(req, DOMAIN)) {
            return;  // 401 challenge already sent
        }
        fixContact(req);
        processRegister(req);
        return;
    }

    // --- INVITE, MESSAGE, SUBSCRIBE, NOTIFY, OPTIONS, INFO, UPDATE ---
    if (/^(INVITE|MESSAGE|SUBSCRIBE|NOTIFY|OPTIONS|INFO|UPDATE|REFER|PUBLISH)$/.test(req.method)) {

        // Authenticate requests from our domain
        if (req.from && req.from.host === DOMAIN) {
            if (!authenticate(req, DOMAIN)) {
                return;
            }
        }

        // Lookup destination in location database
        var contacts = lookup();
        if (contacts && contacts.length > 0) {
            log("routing " + req.method + " to " + contacts[0].contact +
                " via " + contacts[0].receivedIp + ":" + contacts[0].receivedPort);
            proxy(contacts[0]);
        } else {
            log("no registration found for " + req.requestUri.full);
            sendResponse(404, "Not Found");
        }
        return;
    }

    // --- CANCEL ---
    if (req.method === "CANCEL") {
        sendResponse(200, "OK");
        return;
    }

    // --- Anything else ---
    log("rejecting unknown method: " + req.method);
    sendResponse(405, "Method Not Allowed");
}
