<?php

namespace Maklad\Permission\Test;

use Maklad\Permission\Exceptions\PermissionAlreadyExists;
use Maklad\Permission\Models\Permission;
use Maklad\Permission\Models\Role;
use Monolog\Level;
use PHPUnit\Framework\Attributes\Test;

class PermissionTest extends TestCase
{
    #[Test]
    public function test_deleting_permission_removes_role_references_without_inverse_ids(): void
    {
        $permission = $this->testUserPermission;
        $this->testUserRole->givePermissionTo('edit-news', $permission, 'edit-categories');
        $permission->assignRole('testRole2');
        $this->assertArrayNotHasKey('role_ids', $permission->fresh()->getAttributes());

        $permission->delete();

        $remainingIds = Permission::query()->whereIn('name', ['edit-news', 'edit-categories'])->get()->modelKeys();
        $role = $this->testUserRole->fresh();
        $this->assertEqualsCanonicalizing($remainingIds, $role->permission_ids);
        $this->assertSame([0, 1], array_keys($role->permission_ids));
        $this->assertSame([], Role::findByName('testRole2')->permission_ids);
        $this->assertFalse($role->hasPermissionTo($permission));
    }

    #[Test]
    public function test_soft_deleting_permission_preserves_references_until_force_delete(): void
    {
        $permission = SoftDeletingPermission::create(['name' => 'soft-permission']);
        $permission->assignRole('testRole');

        $permission->delete();
        $this->assertSame([$permission->getKey()], $this->testUserRole->fresh()->permission_ids);

        $permission->restore();
        $this->assertTrue($this->testUserRole->fresh()->hasPermissionTo($permission));

        $permission->forceDelete();
        $this->assertSame([], $this->testUserRole->fresh()->permission_ids);
    }

    #[Test]
    public function it_throws_an_exception_when_the_permission_already_exists()
    {
        $can_logs = [true, false];

        foreach ($can_logs as $can_log) {
            config('permission.log_registration_exception', $can_log);

            try {
                $this->expectException(PermissionAlreadyExists::class);

                \app(\config('permission.models.permission'))->create(['name' => 'test-permission']);
                \app(\config('permission.models.permission'))->create(['name' => 'test-permission']);
            } finally {
                $message = $this->helpers->getPermissionAlreadyExistsMessage('test-permission', 'web');
                $this->assertLogMessage($message, Level::Alert);
            }
        }
    }

    #[Test]
    public function it_belongs_to_a_guard()
    {
        $permission = \app(\config('permission.models.permission'))->create(['name' => 'can-edit', 'guard_name' => 'admin']);

        $this->assertEquals('admin', $permission->guard_name);
    }

    #[Test]
    public function it_belongs_to_the_default_guard_by_default()
    {
        $this->assertEquals($this->app['config']->get('auth.defaults.guard'), $this->testUserPermission->guard_name);
    }

    #[Test]
    public function it_has_user_models_of_the_right_class()
    {
        $this->testAdmin->givePermissionTo($this->testAdminPermission);

        $this->testUser->givePermissionTo($this->testUserPermission);

        $this->assertCount(1, $this->testUserPermission->users);
        $this->assertEquals(get_class($this->testUser), get_class($this->testUserPermission->users->first()));
        $this->assertInstanceOf(User::class, $this->testUserPermission->users->first());

        $this->testUser->delete();
        $this->assertEquals(0, $this->testUserPermission->usersQuery()->count());
    }

    #[Test]
    public function it_creates_permission_object_with_findOrCreate_if_it_does_not_have_a_permission_object()
    {
        $permission = app(Permission::class)->findOrCreate('another-permission');
        $this->assertFalse($this->testUserRole->hasPermissionTo($permission));

        $this->testUserRole->givePermissionTo($permission);

        $this->testUserRole = $this->testUserRole->fresh();
        $this->assertTrue($this->testUserRole->hasPermissionTo('another-permission'));
    }
}
