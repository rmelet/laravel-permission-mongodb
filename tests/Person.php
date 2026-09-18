<?php

namespace Maklad\Permission\Test;

class Person extends User
{
    protected $table = 'users';

    protected $guard_name = 'web';
}
