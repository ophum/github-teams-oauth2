// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// AccessTokensColumns holds the columns for the "access_tokens" table.
	AccessTokensColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUUID},
		{Name: "token", Type: field.TypeString},
		{Name: "expires_at", Type: field.TypeTime},
		{Name: "user_access_tokens", Type: field.TypeUUID, Nullable: true},
	}
	// AccessTokensTable holds the schema information for the "access_tokens" table.
	AccessTokensTable = &schema.Table{
		Name:       "access_tokens",
		Columns:    AccessTokensColumns,
		PrimaryKey: []*schema.Column{AccessTokensColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "access_tokens_users_access_tokens",
				Columns:    []*schema.Column{AccessTokensColumns[3]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// CodesColumns holds the columns for the "codes" table.
	CodesColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUUID},
		{Name: "code", Type: field.TypeString},
		{Name: "client_id", Type: field.TypeString, Default: ""},
		{Name: "scope", Type: field.TypeString, Default: ""},
		{Name: "redirect_uri", Type: field.TypeString, Default: ""},
		{Name: "code_challenge", Type: field.TypeString, Default: ""},
		{Name: "expires_at", Type: field.TypeTime},
		{Name: "user_codes", Type: field.TypeUUID, Nullable: true},
	}
	// CodesTable holds the schema information for the "codes" table.
	CodesTable = &schema.Table{
		Name:       "codes",
		Columns:    CodesColumns,
		PrimaryKey: []*schema.Column{CodesColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "codes_users_codes",
				Columns:    []*schema.Column{CodesColumns[7]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// GroupsColumns holds the columns for the "groups" table.
	GroupsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUUID},
		{Name: "name", Type: field.TypeString, Unique: true},
	}
	// GroupsTable holds the schema information for the "groups" table.
	GroupsTable = &schema.Table{
		Name:       "groups",
		Columns:    GroupsColumns,
		PrimaryKey: []*schema.Column{GroupsColumns[0]},
	}
	// UsersColumns holds the columns for the "users" table.
	UsersColumns = []*schema.Column{
		{Name: "id", Type: field.TypeUUID},
		{Name: "name", Type: field.TypeString},
		{Name: "email", Type: field.TypeString},
	}
	// UsersTable holds the schema information for the "users" table.
	UsersTable = &schema.Table{
		Name:       "users",
		Columns:    UsersColumns,
		PrimaryKey: []*schema.Column{UsersColumns[0]},
	}
	// GroupCodesColumns holds the columns for the "group_codes" table.
	GroupCodesColumns = []*schema.Column{
		{Name: "group_id", Type: field.TypeUUID},
		{Name: "code_id", Type: field.TypeUUID},
	}
	// GroupCodesTable holds the schema information for the "group_codes" table.
	GroupCodesTable = &schema.Table{
		Name:       "group_codes",
		Columns:    GroupCodesColumns,
		PrimaryKey: []*schema.Column{GroupCodesColumns[0], GroupCodesColumns[1]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "group_codes_group_id",
				Columns:    []*schema.Column{GroupCodesColumns[0]},
				RefColumns: []*schema.Column{GroupsColumns[0]},
				OnDelete:   schema.Cascade,
			},
			{
				Symbol:     "group_codes_code_id",
				Columns:    []*schema.Column{GroupCodesColumns[1]},
				RefColumns: []*schema.Column{CodesColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
	}
	// GroupAccessTokensColumns holds the columns for the "group_access_tokens" table.
	GroupAccessTokensColumns = []*schema.Column{
		{Name: "group_id", Type: field.TypeUUID},
		{Name: "access_token_id", Type: field.TypeUUID},
	}
	// GroupAccessTokensTable holds the schema information for the "group_access_tokens" table.
	GroupAccessTokensTable = &schema.Table{
		Name:       "group_access_tokens",
		Columns:    GroupAccessTokensColumns,
		PrimaryKey: []*schema.Column{GroupAccessTokensColumns[0], GroupAccessTokensColumns[1]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "group_access_tokens_group_id",
				Columns:    []*schema.Column{GroupAccessTokensColumns[0]},
				RefColumns: []*schema.Column{GroupsColumns[0]},
				OnDelete:   schema.Cascade,
			},
			{
				Symbol:     "group_access_tokens_access_token_id",
				Columns:    []*schema.Column{GroupAccessTokensColumns[1]},
				RefColumns: []*schema.Column{AccessTokensColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
	}
	// UserGroupsColumns holds the columns for the "user_groups" table.
	UserGroupsColumns = []*schema.Column{
		{Name: "user_id", Type: field.TypeUUID},
		{Name: "group_id", Type: field.TypeUUID},
	}
	// UserGroupsTable holds the schema information for the "user_groups" table.
	UserGroupsTable = &schema.Table{
		Name:       "user_groups",
		Columns:    UserGroupsColumns,
		PrimaryKey: []*schema.Column{UserGroupsColumns[0], UserGroupsColumns[1]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "user_groups_user_id",
				Columns:    []*schema.Column{UserGroupsColumns[0]},
				RefColumns: []*schema.Column{UsersColumns[0]},
				OnDelete:   schema.Cascade,
			},
			{
				Symbol:     "user_groups_group_id",
				Columns:    []*schema.Column{UserGroupsColumns[1]},
				RefColumns: []*schema.Column{GroupsColumns[0]},
				OnDelete:   schema.Cascade,
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		AccessTokensTable,
		CodesTable,
		GroupsTable,
		UsersTable,
		GroupCodesTable,
		GroupAccessTokensTable,
		UserGroupsTable,
	}
)

func init() {
	AccessTokensTable.ForeignKeys[0].RefTable = UsersTable
	CodesTable.ForeignKeys[0].RefTable = UsersTable
	GroupCodesTable.ForeignKeys[0].RefTable = GroupsTable
	GroupCodesTable.ForeignKeys[1].RefTable = CodesTable
	GroupAccessTokensTable.ForeignKeys[0].RefTable = GroupsTable
	GroupAccessTokensTable.ForeignKeys[1].RefTable = AccessTokensTable
	UserGroupsTable.ForeignKeys[0].RefTable = UsersTable
	UserGroupsTable.ForeignKeys[1].RefTable = GroupsTable
}
