package user

import (
	"bytes"
	"net/http"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/metatags"
	user_models "github.com/go-bolo/user/models"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var userAlertTriggerControllerLogPrefix = "userAlertTrigger.controller."

type UserAlertTriggerJSONResponse struct {
	bolo.BaseListReponse
	Record *[]*user_models.UserAlertTriggerModel `json:"user_alert_triggers"`
}

type UserAlertTriggerCountJSONResponse struct {
	bolo.BaseMetaResponse
}

type UserAlertTriggerFindOneJSONResponse struct {
	Record *user_models.UserAlertTriggerModel `json:"user_alert_triggers"`
}

type UserAlertTriggerBodyRequest struct {
	Record *user_models.UserAlertTriggerModel `json:"user_alert_triggers"`
}

type UserAlertTriggerTeaserTPL struct {
	Ctx    *bolo.RequestContext
	Record *user_models.UserAlertTriggerModel
}

// Http userAlertTrigger controller | struct with http handlers
type UserAlertTriggerController struct {
}

func (ctl *UserAlertTriggerController) Query(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	var count int64
	records := []*user_models.UserAlertTriggerModel{}
	err = user_models.UserAlertTriggerQueryAndCountFromRequest(&user_models.UserAlertTriggerQueryAndCounttCfg{
		Records: &records,
		Count:   &count,
		Limit:   ctx.GetLimit(),
		Offset:  ctx.GetOffset(),
		C:       c,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug(userAlertTriggerControllerLogPrefix + "query Error on find users")
	}

	ctx.Pager.Count = count

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug(userAlertTriggerControllerLogPrefix + "query count result")

	for i := range records {
		records[i].LoadData()
	}

	resp := UserAlertTriggerJSONResponse{
		Record: &records,
	}

	resp.Meta.Count = count

	return c.JSON(200, &resp)
}

func (ctl *UserAlertTriggerController) Create(c echo.Context) error {
	logrus.Debug(userAlertTriggerControllerLogPrefix + "create running")
	var err error
	ctx := c.(*bolo.RequestContext)

	can := ctx.Can("create_user")
	if !can {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
	}

	var body UserAlertTriggerBodyRequest

	if err := c.Bind(&body); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	record := body.Record
	record.ID = 0

	if err := c.Validate(record); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return err
	}

	logrus.WithFields(logrus.Fields{
		"body": body,
	}).Debug(userAlertTriggerControllerLogPrefix + "create params")

	err = record.Save()
	if err != nil {
		return err
	}

	err = record.LoadData()
	if err != nil {
		return err
	}

	resp := UserAlertTriggerFindOneJSONResponse{
		Record: record,
	}

	return c.JSON(http.StatusCreated, &resp)
}

func (ctl *UserAlertTriggerController) Count(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	var count int64
	err = user_models.UserAlertTriggerCountQueryFromRequest(&user_models.UserAlertTriggerQueryAndCounttCfg{
		Count:  &count,
		Limit:  ctx.GetLimit(),
		Offset: ctx.GetOffset(),
		C:      c,
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug(userAlertTriggerControllerLogPrefix + "count Error on find contents")
	}

	ctx.Pager.Count = count

	resp := UserAlertTriggerCountJSONResponse{}
	resp.Count = count

	return c.JSON(200, &resp)
}

func (ctl *UserAlertTriggerController) FindOne(c echo.Context) error {
	id := c.Param("id")
	ctx := c.(*bolo.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userAlertTriggerControllerLogPrefix + "findOne id from params")

	record := user_models.UserAlertTriggerModel{}
	err := user_models.UserTriggerFindOne(id, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug(userAlertTriggerControllerLogPrefix + "findOne id record not found")

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

	resp := UserAlertTriggerFindOneJSONResponse{
		Record: &record,
	}

	return c.JSON(200, &resp)
}

func (ctl *UserAlertTriggerController) Update(c echo.Context) error {
	var err error

	id := c.Param("id")

	ctx := c.(*bolo.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id":    id,
		"roles": ctx.GetAuthenticatedRoles(),
	}).Debug(userAlertTriggerControllerLogPrefix + "update id from params")

	record := user_models.UserAlertTriggerModel{}
	err = user_models.UserTriggerFindOne(id, &record)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Debug(userAlertTriggerControllerLogPrefix + "update error on find one")
		return errors.Wrap(err, userAlertTriggerControllerLogPrefix+"update error on find one")
	}

	if record.GetID() == ctx.AuthenticatedUser.GetID() {
		ctx.AuthenticatedUser.AddRole("owner")
	}

	if !ctx.Can("update_user") {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
	}

	record.LoadData()

	body := UserAlertTriggerFindOneJSONResponse{Record: &record}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Debug(userAlertTriggerControllerLogPrefix + "update error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	err = record.Save()
	if err != nil {
		return err
	}
	resp := UserAlertTriggerFindOneJSONResponse{
		Record: &record,
	}

	return c.JSON(http.StatusOK, &resp)
}

func (ctl *UserAlertTriggerController) Delete(c echo.Context) error {
	var err error

	id := c.Param("id")

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userAlertTriggerControllerLogPrefix + "delete id from params")

	ctx := c.(*bolo.RequestContext)

	record := user_models.UserAlertTriggerModel{}
	err = user_models.UserTriggerFindOne(id, &record)
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

func (ctl *UserAlertTriggerController) FindAllPageHandler(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.Query(c)
	}

	ctx.Title = "Usuários"
	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = "Usuários no Monitor do Mercado"

	var count int64
	records := []*user_models.UserAlertTriggerModel{}
	err = user_models.UserAlertTriggerQueryAndCountFromRequest(&user_models.UserAlertTriggerQueryAndCounttCfg{
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
		}).Debug(userAlertTriggerControllerLogPrefix + "FindAllPageHandler Error on find contents")
	}

	ctx.Pager.Count = count

	var teaserList []string

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug(userAlertTriggerControllerLogPrefix + "FindAllPageHandler count result")

	for i := range records {
		records[i].LoadTeaserData()

		var teaserHTML bytes.Buffer

		err = ctx.RenderTemplate(&teaserHTML, "user/teaser", UserAlertTriggerTeaserTPL{
			Ctx:    ctx,
			Record: records[i],
		})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"err": err.Error(),
			}).Error(userAlertTriggerControllerLogPrefix + "FindAllPageHandler error on render teaser")
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

func (ctl *UserAlertTriggerController) FindOnePageHandler(c echo.Context) error {
	var err error
	ctx := c.(*bolo.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.FindOne(c)
	}

	id := c.Param("id")

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug(userAlertTriggerControllerLogPrefix + "FindOnePageHandler id from params")

	record := user_models.UserAlertTriggerModel{}
	err = user_models.UserTriggerFindOne(id, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug(userAlertTriggerControllerLogPrefix + "FindOnePageHandler id record not found")
		return echo.NotFoundHandler(c)
	}

	record.LoadData()

	// ctx.Title = record.DisplayName
	ctx.BodyClass = append(ctx.BodyClass, "body-content-findOne")

	// mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	// mt.Title = record.DisplayName
	// mt.Description = record.Biography

	return c.Render(http.StatusOK, "user/findOne", &bolo.TemplateCTX{
		Ctx:    ctx,
		Record: &record,
	})
}
