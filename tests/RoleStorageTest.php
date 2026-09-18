<?php

namespace Maklad\Permission\Test;

use Illuminate\Support\Facades\DB;
use Maklad\Permission\Exceptions\RoleDoesNotExist;
use Maklad\Permission\Models\Role;

class RoleStorageTest extends TestCase
{
    public function test_assignments_from_separate_instances_preserve_both_roles(): void
    {
        $first = $this->testUser->fresh();
        $second = $this->testUser->fresh();

        $first->assignRole('testRole');
        $second->assignRole('testRole2');

        $this->assertEqualsCanonicalizing(
            ['testRole', 'testRole2'],
            $this->testUser->fresh()->getRoleNames()->all()
        );
    }

    public function test_revocations_from_separate_instances_do_not_restore_roles(): void
    {
        $this->testUser->assignRole('testRole', 'testRole2');
        $first = $this->testUser->fresh();
        $second = $this->testUser->fresh();

        $first->removeRole('testRole');
        $second->removeRole('testRole2');

        $this->assertSame([], $this->testUser->fresh()->role_ids);
    }

    public function test_assigning_from_a_stale_instance_does_not_restore_a_revoked_role(): void
    {
        $this->testUser->assignRole('testRole');
        $stale = $this->testUser->fresh();
        $this->testUser->removeRole('testRole');
        $stale->assignRole('testRole2');

        $this->assertSame(['testRole2'], $this->testUser->fresh()->getRoleNames()->all());
    }

    public function test_sync_replaces_roles_in_one_write_even_on_a_stale_instance(): void
    {
        $this->testUser->assignRole('testRole');
        $stale = $this->testUser->fresh();
        $this->testUser->assignRole('testRole2');

        DB::connection()->enableQueryLog();
        DB::flushQueryLog();
        $stale->syncRoles($this->testUserRole);
        $queries = DB::getQueryLog();
        DB::connection()->disableQueryLog();

        $this->assertCount(1, $queries);
        $this->assertSame(['testRole'], $this->testUser->fresh()->getRoleNames()->all());
    }

    public function test_invalid_sync_keeps_existing_roles(): void
    {
        $this->testUser->assignRole('testRole');
        $this->expectException(RoleDoesNotExist::class);

        try {
            $this->testUser->syncRoles('missing-role');
        } finally {
            $this->assertSame(['testRole'], $this->testUser->fresh()->getRoleNames()->all());
        }
    }

    public function test_role_assignment_saves_a_new_person_without_inverse_ids(): void
    {
        $person = new Person(['email' => 'new@example.test']);
        $person->assignRole('testRole', 'testRole');

        $this->assertTrue($person->exists);
        $this->assertCount(1, $person->fresh()->role_ids);
        $this->assertArrayNotHasKey('person_ids', $this->testUserRole->fresh()->getAttributes());
    }

    public function test_person_role_operations_leave_role_documents_unchanged(): void
    {
        $before = Role::all()->map->getAttributes()->all();
        $person = Person::create(['email' => 'person@example.test']);
        $person->assignRole('testRole', 'testRole2');
        $person->assignRole('testRole');
        $this->assertCount(2, $person->fresh()->role_ids);

        $person->removeRole('testRole');
        $this->assertSame(['testRole2'], $person->fresh()->getRoleNames()->all());
        $this->assertSame([0], array_keys($person->fresh()->role_ids));

        $person->syncRoles('testRole');
        $person->delete();

        $this->assertEquals($before, Role::all()->map->getAttributes()->all());
    }
}
