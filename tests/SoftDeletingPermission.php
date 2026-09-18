<?php

namespace Maklad\Permission\Test;

use Illuminate\Database\Eloquent\SoftDeletes;
use Maklad\Permission\Models\Permission;

class SoftDeletingPermission extends Permission
{
    use SoftDeletes;
}
