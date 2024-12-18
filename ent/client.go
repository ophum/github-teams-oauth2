// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"reflect"

	"github.com/google/uuid"
	"github.com/ophum/github-teams-oauth2/ent/migrate"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/code"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// AccessToken is the client for interacting with the AccessToken builders.
	AccessToken *AccessTokenClient
	// Code is the client for interacting with the Code builders.
	Code *CodeClient
	// Group is the client for interacting with the Group builders.
	Group *GroupClient
	// User is the client for interacting with the User builders.
	User *UserClient
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	client := &Client{config: newConfig(opts...)}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.AccessToken = NewAccessTokenClient(c.config)
	c.Code = NewCodeClient(c.config)
	c.Group = NewGroupClient(c.config)
	c.User = NewUserClient(c.config)
}

type (
	// config is the configuration for the client and its builder.
	config struct {
		// driver used for executing database requests.
		driver dialect.Driver
		// debug enable a debug logging.
		debug bool
		// log used for logging on debug mode.
		log func(...any)
		// hooks to execute on mutations.
		hooks *hooks
		// interceptors to execute on queries.
		inters *inters
	}
	// Option function to configure the client.
	Option func(*config)
)

// newConfig creates a new config for the client.
func newConfig(opts ...Option) config {
	cfg := config{log: log.Println, hooks: &hooks{}, inters: &inters{}}
	cfg.options(opts...)
	return cfg
}

// options applies the options on the config object.
func (c *config) options(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
	if c.debug {
		c.driver = dialect.Debug(c.driver, c.log)
	}
}

// Debug enables debug logging on the ent.Driver.
func Debug() Option {
	return func(c *config) {
		c.debug = true
	}
}

// Log sets the logging function for debug mode.
func Log(fn func(...any)) Option {
	return func(c *config) {
		c.log = fn
	}
}

// Driver configures the client driver.
func Driver(driver dialect.Driver) Option {
	return func(c *config) {
		c.driver = driver
	}
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// ErrTxStarted is returned when trying to start a new transaction from a transactional client.
var ErrTxStarted = errors.New("ent: cannot start a transaction within a transaction")

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, ErrTxStarted
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:         ctx,
		config:      cfg,
		AccessToken: NewAccessTokenClient(cfg),
		Code:        NewCodeClient(cfg),
		Group:       NewGroupClient(cfg),
		User:        NewUserClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, errors.New("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:         ctx,
		config:      cfg,
		AccessToken: NewAccessTokenClient(cfg),
		Code:        NewCodeClient(cfg),
		Group:       NewGroupClient(cfg),
		User:        NewUserClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		AccessToken.
//		Query().
//		Count(ctx)
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.AccessToken.Use(hooks...)
	c.Code.Use(hooks...)
	c.Group.Use(hooks...)
	c.User.Use(hooks...)
}

// Intercept adds the query interceptors to all the entity clients.
// In order to add interceptors to a specific client, call: `client.Node.Intercept(...)`.
func (c *Client) Intercept(interceptors ...Interceptor) {
	c.AccessToken.Intercept(interceptors...)
	c.Code.Intercept(interceptors...)
	c.Group.Intercept(interceptors...)
	c.User.Intercept(interceptors...)
}

// Mutate implements the ent.Mutator interface.
func (c *Client) Mutate(ctx context.Context, m Mutation) (Value, error) {
	switch m := m.(type) {
	case *AccessTokenMutation:
		return c.AccessToken.mutate(ctx, m)
	case *CodeMutation:
		return c.Code.mutate(ctx, m)
	case *GroupMutation:
		return c.Group.mutate(ctx, m)
	case *UserMutation:
		return c.User.mutate(ctx, m)
	default:
		return nil, fmt.Errorf("ent: unknown mutation type %T", m)
	}
}

// AccessTokenClient is a client for the AccessToken schema.
type AccessTokenClient struct {
	config
}

// NewAccessTokenClient returns a client for the AccessToken from the given config.
func NewAccessTokenClient(c config) *AccessTokenClient {
	return &AccessTokenClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `accesstoken.Hooks(f(g(h())))`.
func (c *AccessTokenClient) Use(hooks ...Hook) {
	c.hooks.AccessToken = append(c.hooks.AccessToken, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `accesstoken.Intercept(f(g(h())))`.
func (c *AccessTokenClient) Intercept(interceptors ...Interceptor) {
	c.inters.AccessToken = append(c.inters.AccessToken, interceptors...)
}

// Create returns a builder for creating a AccessToken entity.
func (c *AccessTokenClient) Create() *AccessTokenCreate {
	mutation := newAccessTokenMutation(c.config, OpCreate)
	return &AccessTokenCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of AccessToken entities.
func (c *AccessTokenClient) CreateBulk(builders ...*AccessTokenCreate) *AccessTokenCreateBulk {
	return &AccessTokenCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *AccessTokenClient) MapCreateBulk(slice any, setFunc func(*AccessTokenCreate, int)) *AccessTokenCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &AccessTokenCreateBulk{err: fmt.Errorf("calling to AccessTokenClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*AccessTokenCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &AccessTokenCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for AccessToken.
func (c *AccessTokenClient) Update() *AccessTokenUpdate {
	mutation := newAccessTokenMutation(c.config, OpUpdate)
	return &AccessTokenUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *AccessTokenClient) UpdateOne(at *AccessToken) *AccessTokenUpdateOne {
	mutation := newAccessTokenMutation(c.config, OpUpdateOne, withAccessToken(at))
	return &AccessTokenUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *AccessTokenClient) UpdateOneID(id uuid.UUID) *AccessTokenUpdateOne {
	mutation := newAccessTokenMutation(c.config, OpUpdateOne, withAccessTokenID(id))
	return &AccessTokenUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for AccessToken.
func (c *AccessTokenClient) Delete() *AccessTokenDelete {
	mutation := newAccessTokenMutation(c.config, OpDelete)
	return &AccessTokenDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *AccessTokenClient) DeleteOne(at *AccessToken) *AccessTokenDeleteOne {
	return c.DeleteOneID(at.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *AccessTokenClient) DeleteOneID(id uuid.UUID) *AccessTokenDeleteOne {
	builder := c.Delete().Where(accesstoken.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &AccessTokenDeleteOne{builder}
}

// Query returns a query builder for AccessToken.
func (c *AccessTokenClient) Query() *AccessTokenQuery {
	return &AccessTokenQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeAccessToken},
		inters: c.Interceptors(),
	}
}

// Get returns a AccessToken entity by its id.
func (c *AccessTokenClient) Get(ctx context.Context, id uuid.UUID) (*AccessToken, error) {
	return c.Query().Where(accesstoken.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *AccessTokenClient) GetX(ctx context.Context, id uuid.UUID) *AccessToken {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryUser queries the user edge of a AccessToken.
func (c *AccessTokenClient) QueryUser(at *AccessToken) *UserQuery {
	query := (&UserClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := at.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(accesstoken.Table, accesstoken.FieldID, id),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, accesstoken.UserTable, accesstoken.UserColumn),
		)
		fromV = sqlgraph.Neighbors(at.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryGroups queries the groups edge of a AccessToken.
func (c *AccessTokenClient) QueryGroups(at *AccessToken) *GroupQuery {
	query := (&GroupClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := at.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(accesstoken.Table, accesstoken.FieldID, id),
			sqlgraph.To(group.Table, group.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, accesstoken.GroupsTable, accesstoken.GroupsPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(at.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *AccessTokenClient) Hooks() []Hook {
	return c.hooks.AccessToken
}

// Interceptors returns the client interceptors.
func (c *AccessTokenClient) Interceptors() []Interceptor {
	return c.inters.AccessToken
}

func (c *AccessTokenClient) mutate(ctx context.Context, m *AccessTokenMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&AccessTokenCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&AccessTokenUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&AccessTokenUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&AccessTokenDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown AccessToken mutation op: %q", m.Op())
	}
}

// CodeClient is a client for the Code schema.
type CodeClient struct {
	config
}

// NewCodeClient returns a client for the Code from the given config.
func NewCodeClient(c config) *CodeClient {
	return &CodeClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `code.Hooks(f(g(h())))`.
func (c *CodeClient) Use(hooks ...Hook) {
	c.hooks.Code = append(c.hooks.Code, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `code.Intercept(f(g(h())))`.
func (c *CodeClient) Intercept(interceptors ...Interceptor) {
	c.inters.Code = append(c.inters.Code, interceptors...)
}

// Create returns a builder for creating a Code entity.
func (c *CodeClient) Create() *CodeCreate {
	mutation := newCodeMutation(c.config, OpCreate)
	return &CodeCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Code entities.
func (c *CodeClient) CreateBulk(builders ...*CodeCreate) *CodeCreateBulk {
	return &CodeCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *CodeClient) MapCreateBulk(slice any, setFunc func(*CodeCreate, int)) *CodeCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &CodeCreateBulk{err: fmt.Errorf("calling to CodeClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*CodeCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &CodeCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Code.
func (c *CodeClient) Update() *CodeUpdate {
	mutation := newCodeMutation(c.config, OpUpdate)
	return &CodeUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *CodeClient) UpdateOne(co *Code) *CodeUpdateOne {
	mutation := newCodeMutation(c.config, OpUpdateOne, withCode(co))
	return &CodeUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *CodeClient) UpdateOneID(id uuid.UUID) *CodeUpdateOne {
	mutation := newCodeMutation(c.config, OpUpdateOne, withCodeID(id))
	return &CodeUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Code.
func (c *CodeClient) Delete() *CodeDelete {
	mutation := newCodeMutation(c.config, OpDelete)
	return &CodeDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *CodeClient) DeleteOne(co *Code) *CodeDeleteOne {
	return c.DeleteOneID(co.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *CodeClient) DeleteOneID(id uuid.UUID) *CodeDeleteOne {
	builder := c.Delete().Where(code.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &CodeDeleteOne{builder}
}

// Query returns a query builder for Code.
func (c *CodeClient) Query() *CodeQuery {
	return &CodeQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeCode},
		inters: c.Interceptors(),
	}
}

// Get returns a Code entity by its id.
func (c *CodeClient) Get(ctx context.Context, id uuid.UUID) (*Code, error) {
	return c.Query().Where(code.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *CodeClient) GetX(ctx context.Context, id uuid.UUID) *Code {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryUser queries the user edge of a Code.
func (c *CodeClient) QueryUser(co *Code) *UserQuery {
	query := (&UserClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := co.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(code.Table, code.FieldID, id),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, code.UserTable, code.UserColumn),
		)
		fromV = sqlgraph.Neighbors(co.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryGroups queries the groups edge of a Code.
func (c *CodeClient) QueryGroups(co *Code) *GroupQuery {
	query := (&GroupClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := co.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(code.Table, code.FieldID, id),
			sqlgraph.To(group.Table, group.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, code.GroupsTable, code.GroupsPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(co.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *CodeClient) Hooks() []Hook {
	return c.hooks.Code
}

// Interceptors returns the client interceptors.
func (c *CodeClient) Interceptors() []Interceptor {
	return c.inters.Code
}

func (c *CodeClient) mutate(ctx context.Context, m *CodeMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&CodeCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&CodeUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&CodeUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&CodeDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Code mutation op: %q", m.Op())
	}
}

// GroupClient is a client for the Group schema.
type GroupClient struct {
	config
}

// NewGroupClient returns a client for the Group from the given config.
func NewGroupClient(c config) *GroupClient {
	return &GroupClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `group.Hooks(f(g(h())))`.
func (c *GroupClient) Use(hooks ...Hook) {
	c.hooks.Group = append(c.hooks.Group, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `group.Intercept(f(g(h())))`.
func (c *GroupClient) Intercept(interceptors ...Interceptor) {
	c.inters.Group = append(c.inters.Group, interceptors...)
}

// Create returns a builder for creating a Group entity.
func (c *GroupClient) Create() *GroupCreate {
	mutation := newGroupMutation(c.config, OpCreate)
	return &GroupCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Group entities.
func (c *GroupClient) CreateBulk(builders ...*GroupCreate) *GroupCreateBulk {
	return &GroupCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *GroupClient) MapCreateBulk(slice any, setFunc func(*GroupCreate, int)) *GroupCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &GroupCreateBulk{err: fmt.Errorf("calling to GroupClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*GroupCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &GroupCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Group.
func (c *GroupClient) Update() *GroupUpdate {
	mutation := newGroupMutation(c.config, OpUpdate)
	return &GroupUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *GroupClient) UpdateOne(gr *Group) *GroupUpdateOne {
	mutation := newGroupMutation(c.config, OpUpdateOne, withGroup(gr))
	return &GroupUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *GroupClient) UpdateOneID(id uuid.UUID) *GroupUpdateOne {
	mutation := newGroupMutation(c.config, OpUpdateOne, withGroupID(id))
	return &GroupUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Group.
func (c *GroupClient) Delete() *GroupDelete {
	mutation := newGroupMutation(c.config, OpDelete)
	return &GroupDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *GroupClient) DeleteOne(gr *Group) *GroupDeleteOne {
	return c.DeleteOneID(gr.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *GroupClient) DeleteOneID(id uuid.UUID) *GroupDeleteOne {
	builder := c.Delete().Where(group.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &GroupDeleteOne{builder}
}

// Query returns a query builder for Group.
func (c *GroupClient) Query() *GroupQuery {
	return &GroupQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeGroup},
		inters: c.Interceptors(),
	}
}

// Get returns a Group entity by its id.
func (c *GroupClient) Get(ctx context.Context, id uuid.UUID) (*Group, error) {
	return c.Query().Where(group.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *GroupClient) GetX(ctx context.Context, id uuid.UUID) *Group {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryUsers queries the users edge of a Group.
func (c *GroupClient) QueryUsers(gr *Group) *UserQuery {
	query := (&UserClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := gr.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(group.Table, group.FieldID, id),
			sqlgraph.To(user.Table, user.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, true, group.UsersTable, group.UsersPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(gr.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryCodes queries the codes edge of a Group.
func (c *GroupClient) QueryCodes(gr *Group) *CodeQuery {
	query := (&CodeClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := gr.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(group.Table, group.FieldID, id),
			sqlgraph.To(code.Table, code.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, group.CodesTable, group.CodesPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(gr.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryAccessTokens queries the access_tokens edge of a Group.
func (c *GroupClient) QueryAccessTokens(gr *Group) *AccessTokenQuery {
	query := (&AccessTokenClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := gr.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(group.Table, group.FieldID, id),
			sqlgraph.To(accesstoken.Table, accesstoken.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, group.AccessTokensTable, group.AccessTokensPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(gr.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *GroupClient) Hooks() []Hook {
	return c.hooks.Group
}

// Interceptors returns the client interceptors.
func (c *GroupClient) Interceptors() []Interceptor {
	return c.inters.Group
}

func (c *GroupClient) mutate(ctx context.Context, m *GroupMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&GroupCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&GroupUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&GroupUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&GroupDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown Group mutation op: %q", m.Op())
	}
}

// UserClient is a client for the User schema.
type UserClient struct {
	config
}

// NewUserClient returns a client for the User from the given config.
func NewUserClient(c config) *UserClient {
	return &UserClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `user.Hooks(f(g(h())))`.
func (c *UserClient) Use(hooks ...Hook) {
	c.hooks.User = append(c.hooks.User, hooks...)
}

// Intercept adds a list of query interceptors to the interceptors stack.
// A call to `Intercept(f, g, h)` equals to `user.Intercept(f(g(h())))`.
func (c *UserClient) Intercept(interceptors ...Interceptor) {
	c.inters.User = append(c.inters.User, interceptors...)
}

// Create returns a builder for creating a User entity.
func (c *UserClient) Create() *UserCreate {
	mutation := newUserMutation(c.config, OpCreate)
	return &UserCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of User entities.
func (c *UserClient) CreateBulk(builders ...*UserCreate) *UserCreateBulk {
	return &UserCreateBulk{config: c.config, builders: builders}
}

// MapCreateBulk creates a bulk creation builder from the given slice. For each item in the slice, the function creates
// a builder and applies setFunc on it.
func (c *UserClient) MapCreateBulk(slice any, setFunc func(*UserCreate, int)) *UserCreateBulk {
	rv := reflect.ValueOf(slice)
	if rv.Kind() != reflect.Slice {
		return &UserCreateBulk{err: fmt.Errorf("calling to UserClient.MapCreateBulk with wrong type %T, need slice", slice)}
	}
	builders := make([]*UserCreate, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		builders[i] = c.Create()
		setFunc(builders[i], i)
	}
	return &UserCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for User.
func (c *UserClient) Update() *UserUpdate {
	mutation := newUserMutation(c.config, OpUpdate)
	return &UserUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *UserClient) UpdateOne(u *User) *UserUpdateOne {
	mutation := newUserMutation(c.config, OpUpdateOne, withUser(u))
	return &UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *UserClient) UpdateOneID(id uuid.UUID) *UserUpdateOne {
	mutation := newUserMutation(c.config, OpUpdateOne, withUserID(id))
	return &UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for User.
func (c *UserClient) Delete() *UserDelete {
	mutation := newUserMutation(c.config, OpDelete)
	return &UserDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *UserClient) DeleteOne(u *User) *UserDeleteOne {
	return c.DeleteOneID(u.ID)
}

// DeleteOneID returns a builder for deleting the given entity by its id.
func (c *UserClient) DeleteOneID(id uuid.UUID) *UserDeleteOne {
	builder := c.Delete().Where(user.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &UserDeleteOne{builder}
}

// Query returns a query builder for User.
func (c *UserClient) Query() *UserQuery {
	return &UserQuery{
		config: c.config,
		ctx:    &QueryContext{Type: TypeUser},
		inters: c.Interceptors(),
	}
}

// Get returns a User entity by its id.
func (c *UserClient) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	return c.Query().Where(user.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *UserClient) GetX(ctx context.Context, id uuid.UUID) *User {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryGroups queries the groups edge of a User.
func (c *UserClient) QueryGroups(u *User) *GroupQuery {
	query := (&GroupClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := u.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(user.Table, user.FieldID, id),
			sqlgraph.To(group.Table, group.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, user.GroupsTable, user.GroupsPrimaryKey...),
		)
		fromV = sqlgraph.Neighbors(u.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryCodes queries the codes edge of a User.
func (c *UserClient) QueryCodes(u *User) *CodeQuery {
	query := (&CodeClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := u.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(user.Table, user.FieldID, id),
			sqlgraph.To(code.Table, code.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, user.CodesTable, user.CodesColumn),
		)
		fromV = sqlgraph.Neighbors(u.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryAccessTokens queries the access_tokens edge of a User.
func (c *UserClient) QueryAccessTokens(u *User) *AccessTokenQuery {
	query := (&AccessTokenClient{config: c.config}).Query()
	query.path = func(context.Context) (fromV *sql.Selector, _ error) {
		id := u.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(user.Table, user.FieldID, id),
			sqlgraph.To(accesstoken.Table, accesstoken.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, user.AccessTokensTable, user.AccessTokensColumn),
		)
		fromV = sqlgraph.Neighbors(u.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *UserClient) Hooks() []Hook {
	return c.hooks.User
}

// Interceptors returns the client interceptors.
func (c *UserClient) Interceptors() []Interceptor {
	return c.inters.User
}

func (c *UserClient) mutate(ctx context.Context, m *UserMutation) (Value, error) {
	switch m.Op() {
	case OpCreate:
		return (&UserCreate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdate:
		return (&UserUpdate{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpUpdateOne:
		return (&UserUpdateOne{config: c.config, hooks: c.Hooks(), mutation: m}).Save(ctx)
	case OpDelete, OpDeleteOne:
		return (&UserDelete{config: c.config, hooks: c.Hooks(), mutation: m}).Exec(ctx)
	default:
		return nil, fmt.Errorf("ent: unknown User mutation op: %q", m.Op())
	}
}

// hooks and interceptors per client, for fast access.
type (
	hooks struct {
		AccessToken, Code, Group, User []ent.Hook
	}
	inters struct {
		AccessToken, Code, Group, User []ent.Interceptor
	}
)
