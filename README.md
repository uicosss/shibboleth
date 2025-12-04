# University of Illinois
## Shibboleth

PHP library for using Shibboleth for authentication and authorization.

## Usage
To use the library, you need to:

### Composer 
```
composer require uicosss/shibboleth
require_once 'vendor/autoload.php';
```

### Deploy asset files
This script will copy all the asset files to the full path provided. Can then modify these templates as desired. Along with copying the allowed.netids.example file where needed. File permissions may need to be adjusted to modify the deployed files. 
```
php vendor/uicosss/shibboleth/scripts/deploy-assets.php /full/path/to/deploy/assets
```


### ENV Config
These environment (`$_ENV`) variables must be set within the application using this package. 
```
APP_DOCUMENT_ROOT - e.g. APP_DOCUMENT_ROOT=/var/www/app/assets - Primary absolute directory path, without trailing slash, to where to find an allowed.netids file. This must be set in the application's ENV variables.
APP_STATE - e.g. APP_STATE=LOCAL - [optional] Current application state: local/dev/qa/prod. This is used to force Shib to auth in local environments. This must be set in the application's ENV variables.
WEBMASTER_EMAIL - An email address that will be displayed on auth issue pages.
WEBMASTER_URL - Website that users will be linked to on auth issue pages.
WEBMASTER_OFFICE_TITLE - Name of department or group that users will see on auth issue pages.
```

### Instantiate an object
With or without `$authorizationContext` as a parameter. `$authorizationContext` is an optional parameter that defines a secondary absolute directory path, without trailing slash, to where to find an allowed.netids file. This can be useful when different authorization is needed from the global `APP_DOCUMENT_ROOT` authorization file, for a specific part of the application. 
```
$Shibboleth = new Uicosss\Shibboleth\Shibboleth();
// or with $authorizationContext
$Shibboleth = new Uicosss\Shibboleth\Shibboleth('/var/www/app/alt/assets');
```

### Checking if authenticated
This is the first check when using this library. It confirms that there is a user logged in via Shibboleth.
```
if (!$Shibboleth->isAuthenticated()) {
    $Shibboleth->authenticationMarkup();
    die;
}
```

### Checking if authorized
This is the second check when using this library. It checks any allowed.netids file it can find to verify permissions for the user.
```
if (!$Shibboleth->isAuthorized()) {
    $Shibboleth->forbiddenMarkup();
    die;
}
```

### Rendering auth issues shortcut
A built-in method can automatically handle authentication and authorization issues and render HTML markup. Pass an absolute path to the directory containing the HTML files either copied from the package or custom-made. The filenames should still match what is expected `authentication.html` and `forbidden.html`.
```
$Shibboleth->renderAuthIssues('/var/www/app/assets');
```

## Testing
You can run the unit tests by executing this command from the project root.
```
./vendor/bin/phpunit --colors --verbose
```