<?php

namespace Maklad\Permission\Test;

use Illuminate\Support\Facades\DB;
use Maklad\Permission\Models\Permission;

class RoleLoadingTest extends TestCase
{
    public function test_single_loader_reuses_roles_for_reads_and_serialization(): void
    {
        $this->testUser->assignRole('testRole');
        $this->assertSame($this->testUser, User::loadRolesForModel($this->testUser));

        $this->startQueryLog();
        $this->assertTrue($this->testUser->hasRole('testRole'));
        $this->assertSame(['testRole'], $this->testUser->getRoleNames()->all());
        $this->assertSame('testRole', $this->testUser->toArray()['roles'][0]['name']);
        $this->assertQueryCount(0);
    }

    public function test_batch_loader_uses_one_query_for_paginated_people(): void
    {
        $this->testUser->assignRole('testRole');
        $other = User::create(['email' => 'other@example.test']);
        $other->assignRole('testRole2');
        $people = User::query()->paginate(10);

        $this->startQueryLog();
        $loaded = User::loadRolesFor($people);
        $this->assertSame($people->getCollection(), $loaded);
        $this->assertSame(['testRole'], $loaded->firstWhere('email', 'test@user.com')->getRoleNames()->all());
        $this->assertSame(['testRole2'], $loaded->firstWhere('email', 'other@example.test')->getRoleNames()->all());
        $this->assertCount(2, $people->toArray()['data']);
        $this->assertQueryCount(1);
    }

    public function test_empty_roles_are_cached_without_queries(): void
    {
        $users = User::all();
        $this->startQueryLog();
        User::loadRolesFor($users);

        $this->assertTrue($users->first()->roles->isEmpty());
        $this->assertSame([], $users->toArray()[0]['roles']);
        $this->assertTrue(User::loadRolesFor(collect())->isEmpty());
        $this->assertQueryCount(0);
    }

    public function test_batch_loader_handles_people_with_no_roles_in_a_mixed_list(): void
    {
        $this->testUser->assignRole('testRole');
        $other = User::create(['email' => 'empty@example.test']);
        $users = collect([$this->testUser, $other]);

        $this->startQueryLog();
        User::loadRolesFor($users);
        $this->assertTrue($this->testUser->hasRole('testRole'));
        $this->assertFalse($other->hasRole('testRole'));
        $this->assertSame([], $users->toArray()[1]['roles']);
        $this->assertQueryCount(1);
    }

    public function test_role_changes_invalidate_preloaded_roles(): void
    {
        User::loadRolesForModel($this->testUser);
        $this->testUser->assignRole('testRole');
        $this->assertTrue($this->testUser->hasRole('testRole'));

        User::loadRolesForModel($this->testUser);
        $this->testUser->removeRole('testRole');
        $this->assertFalse($this->testUser->hasRole('testRole'));

        $this->testUser->assignRole('testRole');
        User::loadRolesForModel($this->testUser);
        $this->testUser->syncRoles('testRole2');
        $this->assertSame(['testRole2'], $this->testUser->getRoleNames()->all());
    }

    public function test_permission_single_loader_uses_its_inverse_query_and_invalidates_on_changes(): void
    {
        $permission = $this->testUserPermission;
        $permission->assignRole('testRole');
        Permission::loadRolesForModel($permission);

        $this->startQueryLog();
        $this->assertSame(['testRole'], $permission->getRoleNames()->all());
        $this->assertSame('testRole', $permission->toArray()['roles'][0]['name']);
        $this->assertQueryCount(0);

        $permission->removeRole('testRole');
        $this->assertTrue($permission->roles->isEmpty());
        Permission::loadRolesForModel($permission);
        $permission->assignRole('testRole');
        $this->assertTrue($permission->hasRole('testRole'));
        Permission::loadRolesForModel($permission);
        $permission->syncRoles('testRole2');
        $this->assertSame(['testRole2'], $permission->getRoleNames()->all());
    }

    private function startQueryLog(): void
    {
        DB::connection()->enableQueryLog();
        DB::flushQueryLog();
    }

    private function assertQueryCount(int $expected): void
    {
        $queries = DB::getQueryLog();
        DB::connection()->disableQueryLog();
        $this->assertCount($expected, $queries);
    }
}
