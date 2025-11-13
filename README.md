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
This script will copy all the asset files to the full path provided. Can then modify these templates as desired. Along with copying the allowed.netids.example file where needed.
```
composer run-script deploy-assets -- /full/path/where/to/deploy/assets
```


### Config
```
authorizationContext - Primary directory path, without trailing slash, to where to find an allowed.netids file.
appDocumentRoot - [optional] Secondary directory path, without trailing slash, to where to find an allowed.netids file.
appState - [optional] Current application state: local/dev/qa/prod. This is used to force Shib to auth in local environments.
```

### Instantiate an object of the class with array of config options set
```
$config = [
    'authorizationContext' => '/path/to/file/dir',
    'appDocumentRoot' => '/path/to/alt/file/dir',
    'appState' => 'local',
];
$Shibboleth = new Uicosss\Shibboleth\Shibboleth($config);
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

## Testing
You can run the unit tests by executing this command from the project root.
```
./vendor/bin/phpunit --colors --verbose
```