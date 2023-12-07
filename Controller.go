package user

import (
	"bytes"
	"net/http"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/acl"
	"github.com/go-bolo/metatags"
	user_models "github.com/go-bolo/user/models"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var userControllerLogPrefix = "user.controller."

type ListJSONResponse struct {
	bolo.BaseListReponse
	Record *[]*user_models.UserModel `json:"user"`
}

type CountJSONResponse struct {
	bolo.BaseMetaResponse
}

type FindOneJSONResponse struct {
	Record *user_models.UserModel `json:"user"`
}

type RequestBody struct {
	Record *user_models.UserModel `json:"user"`
}

type TeaserTPL struct {
	Ctx    *bolo.RequestContext
	Record *user_models.UserModel
}

// Http user controller | struct with http handlers
type Controller struct {
	App bolo.App
}

func (ctl *Controller) Query(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	var count int64
	records := []*user_models.UserModel{}
	err = user_models.QueryAndCountFromRequest(&user_models.QueryAndCountFromRequestCfg{
		Records: &records,
		Count:   &count,
		Limit:   ctx.GetLimit(),
		Offset:  ctx.GetOffset(),
		C:       c,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug(userControllerLogPrefix + "query Error on find users")
	}

	ctx.Pager.Count = count

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug(userControllerLogPrefix + "query count result")

	for i := range records {
		records[i].LoadData()
	}

	resp := ListJSONResponse{
		Record: &records,
	}

	resp.Meta.Count = count

	return c.JSON(200, &resp)
}

func (ctl *Controller) Create(c echo.Context) error {
	logrus.Debug(userControllerLogPrefix + "create running")
	var err error
	ctx := c.(*bolo.RequestContext)

	can := ctx.Can("create_user")
	if !can {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
	}

	var body RequestBody

	if err := c.Bind(&body); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	record := body.Record
	record.ID = 0
	record.Username = uuid.New().String()

	if err := c.Validate(record); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return err
	}

	logrus.WithFields(logrus.Fields{
		"body": body,
	}).Debug(userControllerLogPrefix + "create params")

	err = record.Save(ctx)
	if err != nil {
		return err
	}

	err = record.LoadData()
	if err != nil {
		return err
	}

	resp := FindOneJSONResponse{
		Record: record,
	}

	return c.JSON(http.StatusCreated, &resp)
}

func (ctl *Controller) Count(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	var count int64
	err = user_models.CountQueryFromRequest(&user_models.QueryAndCountFromRequestCfg{
		Count:  &count,
		Limit:  ctx.GetLimit(),
		Offset: ctx.GetOffset(),
		C:      c,
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug(userControllerLogPrefix + "count Error on find contents")
	}

	ctx.Pager.Count = count

	resp := CountJSONResponse{}
	resp.Count = count

	return c.JSON(200, &resp)
}

func (ctl *Controller) FindOne(c echo.Context) error {
	id := c.Param("id")
	ctx := c.(*bolo.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userControllerLogPrefix + "findOne id from params")

	record := user_models.UserModel{}
	err := user_models.UserFindOne(id, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug(userControllerLogPrefix + "findOne id record not found")

		return echo.NotFoundHandler(c)
	}

	if ctx.IsAuthenticated {
		if record.GetID() == ctx.AuthenticatedUser.GetID() {
			ctx.AuthenticatedUser.AddRole("owner")
		}
	}

	can := ctx.Can("find_user")
	if !can {
		return &bolo.HTTPError{
			Code:     403,
			Message:  "Forbidden",
			Internal: errors.New("user.FindOne forbidden"),
		}
	}

	record.LoadData()

	resp := FindOneJSONResponse{
		Record: &record,
	}

	return c.JSON(200, &resp)
}

func (ctl *Controller) Update(c echo.Context) error {
	var err error

	id := c.Param("id")

	ctx := c.(*bolo.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id":    id,
		"roles": ctx.GetAuthenticatedRoles(),
	}).Debug(userControllerLogPrefix + "update id from params")

	record := user_models.UserModel{}
	err = user_models.UserFindOne(id, &record)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Debug(userControllerLogPrefix + "update error on find one")
		return errors.Wrap(err, userControllerLogPrefix+"update error on find one")
	}

	if record.GetID() == ctx.AuthenticatedUser.GetID() {
		ctx.Roles = append(ctx.Roles, "owner")
	}

	if !ctx.Can("update_user") {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
	}

	record.LoadData()

	body := FindOneJSONResponse{Record: &record}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Debug(userControllerLogPrefix + "update error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	err = record.Save(ctx)
	if err != nil {
		return err
	}
	resp := FindOneJSONResponse{
		Record: &record,
	}

	return c.JSON(http.StatusOK, &resp)
}

func (ctl *Controller) Delete(c echo.Context) error {
	var err error

	id := c.Param("id")

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userControllerLogPrefix + "delete id from params")

	ctx := c.(*bolo.RequestContext)

	record := user_models.UserModel{}
	err = user_models.UserFindOne(id, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		return c.JSON(http.StatusNotFound, make(map[string]string))
	}

	if record.GetID() == ctx.AuthenticatedUser.GetID() {
		ctx.AuthenticatedUser.AddRole("owner")
	}

	if !ctx.Can("delete_user") {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
	}

	err = record.Delete()
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusNoContent)
}

func (ctl *Controller) FindAllPageHandler(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.Query(c)
	}

	ctx.Title = "Usuários"
	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = "Usuários"

	var count int64
	records := []*user_models.UserModel{}
	err = user_models.QueryAndCountFromRequest(&user_models.QueryAndCountFromRequestCfg{
		Records: &records,
		Count:   &count,
		Limit:   ctx.GetLimit(),
		Offset:  ctx.GetOffset(),
		C:       c,
		IsHTML:  true,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug(userControllerLogPrefix + "FindAllPageHandler Error on find contents")
	}

	ctx.Pager.Count = count

	var teaserList []string

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug(userControllerLogPrefix + "FindAllPageHandler count result")

	for i := range records {
		records[i].LoadTeaserData()

		var teaserHTML bytes.Buffer

		err = ctx.RenderTemplate(&teaserHTML, "user/teaser", TeaserTPL{
			Ctx:    ctx,
			Record: records[i],
		})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"err": err.Error(),
			}).Error(userControllerLogPrefix + "FindAllPageHandler error on render teaser")
		} else {
			teaserList = append(teaserList, teaserHTML.String())
		}
	}

	ctx.Set("hasRecords", true)
	ctx.Set("records", teaserList)

	return c.Render(http.StatusOK, "user/findAll", &bolo.TemplateCTX{
		Ctx: ctx,
	})
}

func (ctl *Controller) FindOnePageHandler(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.FindOne(c)
	}

	id := c.Param("id")

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userControllerLogPrefix + "FindOnePageHandler id from params")

	record := user_models.UserModel{}
	err = user_models.UserFindOne(id, &record)
	if err != nil {

	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug(userControllerLogPrefix + "FindOnePageHandler id record not found")
		return echo.NotFoundHandler(c)
	}

	record.LoadData()

	ctx.Title = record.DisplayName
	ctx.BodyClass = append(ctx.BodyClass, "body-content-findOne")

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = record.DisplayName
	mt.Description = record.Biography

	return c.Render(http.StatusOK, "user/findOne", &bolo.TemplateCTX{
		Ctx:    ctx,
		Record: &record,
	})
}

type UserRolesResponse struct {
	Roles       map[string]*acl.Role `json:"roles"`
	Permissions string               `json:"permissions"`
}

func (ctl *Controller) GetUserRolesAndPermissions(c echo.Context) error {
	ctx := c.(*bolo.RequestContext)
	appStruct := ctx.App.(*bolo.AppStruct)
	r := UserRolesResponse{Roles: appStruct.RolesList}

	return c.JSON(http.StatusOK, &r)
}
func (ctl *Controller) GetUserRoles(c echo.Context) error {
	return c.String(http.StatusNotImplemented, "Not implemented")
}

type UserRolesBodyRequest struct {
	UserRoles []string `json:"userRoles"`
}

func (ctl *Controller) UpdateUserRoles(c echo.Context) error {
	userID := c.Param("userID")
	ctx := c.(*bolo.RequestContext)

	var user user_models.UserModel
	err := user_models.UserFindOne(userID, &user)
	if err != nil {
		return err
	}

	if user.ID == 0 {
		return &bolo.HTTPError{
			Code:    404,
			Message: "not found",
		}
	}

	body := UserRolesBodyRequest{}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("user.UpdateUserRoles error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	err = user.SetRoles(body.UserRoles)
	if err != nil {
		return err
	}

	err = user.Save(ctx)
	if err != nil {
		return errors.Wrap(err, "user.UpdateUserRoles error on save user roles")
	}

	return c.JSON(http.StatusOK, make(map[string]string))
}

type ControllerCfg struct {
	App bolo.App
}

func NewController(cfg *ControllerCfg) *Controller {
	ctx := Controller{App: cfg.App}

	return &ctx
}

type RoleTableItem struct {
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
	Role    string `json:"role"`
}

// func buildUserRolesVar(userRoles []string, app bolo.App) ([]RoleTableItem, error) {

// 	appStruct := app.(*bolo.AppStruct)

// 	for _, r := range userRoles {

// 	}

// 	return []RoleTableItem{}, nil
// }
