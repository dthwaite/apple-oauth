/* global OAuth */
import Apple from "./namespace.js";
import { Accounts } from "meteor/accounts-base";
import semver from "semver-lite";
import { getClientIdFromOptions, stateParam } from "./utils";

/**
 * Request Apple credentials for the user (boilerplate).
 * Called from accounts-apple.
 *
 * @param {Object}    options                             Optional
 * @param {Function}  credentialRequestCompleteCallback   Callback function to call on completion. Takes one argument, credentialToken on success, or Error on error.
 */
Apple.requestCredential = function (options, oauthCallback, nativeCallback) {
    const nativeFlow = hasSupportForNativeLogin();

    let credentialRequestCompleteCallback = nativeFlow ?
        nativeCallback :
        oauthCallback;
    // Support both (options, callback) and (callback).
    if (!credentialRequestCompleteCallback && typeof options === "function") {
        credentialRequestCompleteCallback = options;
        options = {};
    } else if (!options) {
        options = {};
    }
    const config = ServiceConfiguration.configurations.findOne({
        service: "apple",
    });
    if (!config) {
        credentialRequestCompleteCallback &&
        credentialRequestCompleteCallback(new ServiceConfiguration.ConfigError());
        return;
    }
    if (!nativeFlow) {
        const credentialToken = Random.secret();
        const loginStyle = Apple._isNativeSignInWindow() ?
            "redirect" :
            OAuth._loginStyle("apple", config, options);
        const scope =
            options && options.requestPermissions ?
                options.requestPermissions.join("%20") :
                "name%20email";

        let redirectUrl = (options && options.absoluteUrlOptions && options.absoluteUrlOptions.rootUrl) || config.redirectUri;
        if (options && options.redirectUrl) redirectUrl=options.redirectUrl;
        const redirectUriWithOauth = redirectUrl.includes('/_oauth/apple') ? redirectUrl : `${redirectUrl}${redirectUrl.endsWith('/') ? '' : '/'}_oauth/apple`;

        const loginUrl =
            "https://appleid.apple.com/auth/authorize" +
            "?response_type=code%20id_token" +
            "&response_mode=form_post" +
            `&redirect_uri=${redirectUriWithOauth}` +
            `&client_id=${getClientIdFromOptions(options, config)}` +
            `&scope=${scope}` +
            `&state=${stateParam({loginStyle, credentialToken, redirectUrl, shard: options.shard})}`;

        OAuth.launchLogin({
            loginService: "apple",
            loginStyle,
            loginUrl,
            credentialRequestCompleteCallback,
            credentialToken,
            popupOptions: {
                height: 600,
            },
        });
        return;
    }

    const scope = [];
    const requestPermissions = (options && options.requestPermissions) || [];
    if (requestPermissions.includes("name")) {
        scope.push(0);
    }
    if (requestPermissions.includes("email")) {
        scope.push(1);
    }

    window.cordova.plugins.SignInWithApple.signin({requestedScopes: scope},
        function (succ) {
            Accounts.callLoginMethod({
                methodArguments: [
                    {...succ, code: succ.authorizationCode, methodName: "native-apple"},
                ],
                userCallback: credentialRequestCompleteCallback,
            });
        },
        function (err) {
            console.error("err", err);
            if (err.code && err.code==='1001') err=new Accounts.LoginCancelledError('Apple login cancelled');
            credentialRequestCompleteCallback(err);
        }
    );
};

function hasSupportForNativeLogin() {
    if (!Meteor.isCordova) return false;

    const isiOS = device.platform === "iOS";

    if (!isiOS) return false;

    let version = device.version.split('.');

    // Apple doesn't follow semver all the time, so fix it to look like major.minor.patch
    while (version.length < 3) {
        version = version.concat([0]);
    }
    return isiOS && semver.gte(version.join('.'), "13.0.0");
}

/**
 * Checks if browser uses native sign in window
 *
 * webkit >=605 on iOS and macos shows sign in with apple as native ui screen
 * and then we need to use a redirect login style
 *
 * (Would like to have a better way to check this but it works for now)
 */
Apple._isNativeSignInWindow = function () {
    const minVersionNative = 605;
    const userAgent = ((navigator && navigator.userAgent) || "").toLowerCase();
    const match = userAgent.match(/applewebkit\/(\d+)/);
    if (match === null) {
        return false;
    }
    const version = match[1];
    return version >= minVersionNative;
};
