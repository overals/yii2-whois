Yii2 Whois
=====================

PHP class to retrieve WHOIS information.

## Installation

```bash
$ php composer.phar require overals/yii2-whois "~1.0.1"
```

#### OR

Add to your `composer.json`

```json
{
    "require": {
        "overals/yii2-whois": "~1.0.1"
    }
}
```

and run

```bash
$ composer update
```

## Example of usage

```php

<?php

$domainName = 'wtools.io';

$domain = new \overals\whois\Whois($domainName);
$whois_answer = $domain->info();

echo $whois_answer;

if ($domain->isAvailable()) {
    echo "Domain is available\n";
} else {
    echo "Domain is registered\n";
}

```