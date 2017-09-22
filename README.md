# vanilla-connect

## Usage example

```php
// If you did not use composer to install this library uncomment the following line.
//require_once PATH_TO_VANILLA_CONNECT_FOLDER.'/vendor/autoload.php';

// 1. Get your client ID and secret here. These must match those in your VanillaConnect settings.
$clientID = "1234";
$secret = "1234";

// 2. Grab the current user from your session management system or database here.
$signedIn = true; // this is just a placeholder

// YOUR CODE HERE.

// 3. Fill in the user information in a way that Vanilla can understand.
$user = [];
if ($signedIn) {
    // CHANGE THESE FOUR LINES.
    $user['id'] = '123'; // This is required no matter what.
    $user['name'] = 'John PHP';
    $user['email'] = 'john.php@example.com';
    $user['photourl'] = '';
}

// 4. Generate the VanillaConnect JWT.
$vanillaConnect = new VanillaConnectProvider($clientID, $secret);
$jwt = $vanillaConnect->authenticate($_GET['jwt'], $user);

$vanillaConnect->addRedirectUrl('....')
$vanillaConnect->addRedirectUrl('....')
$vanillaConnect->redirect($_GET);

// 5. Redirect to your forum with the generated JSON Web Token ($jwt)
header("Location: https://forum.example.com/api/v2/sso/authenticate/vanilla-connect/$clientID?jwt=$jwt"
```

## Making it work for multiple forums

If you have the need to make this work for multiple forums you can check for the `Target` parameter like so:
```php
// List of forums that you own.
// It is important to validate that the requested Target is trusted.
$validTargets = [
    'https://forum.production.example.com',
    'https://forum.staging.example.com',
    ...
];

if (!empty($_REQUEST['Target']) && in_array($_REQUEST['Target'], $validTargets)) {
    $taget = $_REQUEST['Target'];
} else {
    // You can either die() with en error message or you can default to your main forum.
    // In this example we will default to the main forum.
    $target = $validTargets[0];
}

...

// 5. Redirect to your forum with the generated JSON Web Token ($jwt)
header("Location: $target/api/v2/sso/authenticate/vanilla-connect/$clientID?jwt=$jwt"
```
