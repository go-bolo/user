package user

import (
	"bytes"
	"net/http"

	"github.com/go-catupiry/catu"
	"github.com/go-catupiry/metatags"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type ListJSONResponse struct {
	catu.BaseListReponse
	Record *[]*UserModel `json:"user"`
}

type CountJSONResponse struct {
	catu.BaseMetaResponse
}

type FindOneJSONResponse struct {
	Record *UserModel `json:"user"`
}

type RequestBody struct {
	Record *UserModel `json:"user"`
}

type TeaserTPL struct {
	Ctx    *catu.RequestContext
	Record *UserModel
}

// Http user controller | struct with http handlers
type Controller struct {
}

func (ctl *Controller) Query(c echo.Context) error {
	var err error
	ctx := c.(*catu.RequestContext)

	var count int64
	var records []*UserModel
	err = QueryAndCountFromRequest(&QueryAndCountFromRequestCfg{
		Records: &records,
		Count:   &count,
		Limit:   ctx.GetLimit(),
		Offset:  ctx.GetOffset(),
		C:       c,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("Query Error on find users")
	}

	ctx.Pager.Count = count

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug("Query count result")

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
	logrus.Debug("Controller.Create running")
	var err error
	ctx := c.(*catu.RequestContext)

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

	if err := c.Validate(record); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return err
	}

	logrus.WithFields(logrus.Fields{
		"body": body,
	}).Info("Controller.Create params")

	err = record.Save()
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
	ctx := c.(*catu.RequestContext)

	var count int64
	err = CountQueryFromRequest(&QueryAndCountFromRequestCfg{
		Count:  &count,
		Limit:  ctx.GetLimit(),
		Offset: ctx.GetOffset(),
		C:      c,
	})

	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("ContentFindAll Error on find contents")
	}

	ctx.Pager.Count = count

	resp := CountJSONResponse{}
	resp.Count = count

	return c.JSON(200, &resp)
}

func (ctl *Controller) FindOne(c echo.Context) error {
	id := c.Param("id")
	ctx := c.(*catu.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug("ContentFindOne id from params")

	record := UserModel{}
	err := UserFindOne(id, &record)
	if err != nil {
		return err
	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug("FindOneHandler id record not found")

		return echo.NotFoundHandler(c)
	}

	if record.GetID() == ctx.AuthenticatedUser.GetID() {
		ctx.AuthenticatedUser.AddRole("owner")
	}

	can := ctx.Can("find_user")
	if !can {
		return echo.NewHTTPError(http.StatusForbidden, "Forbidden")
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

	ctx := c.(*catu.RequestContext)

	logrus.WithFields(logrus.Fields{
		"id":    id,
		"roles": ctx.GetAuthenticatedRoles(),
	}).Debug("user.Controller.Update id from params")

	record := UserModel{}
	err = UserFindOne(id, &record)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Debug("user.Controller.Update error on find one")
		return errors.Wrap(err, "user.Controller.Update error on find one")
	}

	if record.GetID() == ctx.AuthenticatedUser.GetID() {
		ctx.AuthenticatedUser.AddRole("owner")
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
		}).Debug("user.Controller.Update error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return err
		}
		return c.NoContent(http.StatusNotFound)
	}

	err = record.Save()
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
	}).Debug("user.Controller.Delete id from params")

	ctx := c.(*catu.RequestContext)

	record := UserModel{}
	err = UserFindOne(id, &record)
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
	ctx := c.(*catu.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.FindOne(c)
	}

	ctx.Title = "Usuários"

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = "Usuários"

	var count int64
	var records []*UserModel
	err = QueryAndCountFromRequest(&QueryAndCountFromRequestCfg{
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
		}).Debug("ContentFindAll Error on find contents")
	}

	ctx.Pager.Count = count

	var teaserList []string

	logrus.WithFields(logrus.Fields{
		"count":             count,
		"len_records_found": len(records),
	}).Debug("ContentFindAll count result")

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
			}).Error("controlers.ContentFindAll error on render teaser")
		} else {
			teaserList = append(teaserList, teaserHTML.String())
		}
	}

	ctx.Set("hasRecords", true)
	ctx.Set("records", teaserList)

	return c.Render(http.StatusOK, "user/findAll", &catu.TemplateCTX{
		Ctx: ctx,
	})
}

func (ctl *Controller) FindOnePageHandler(c echo.Context) error {
	var err error
	ctx := c.(*catu.RequestContext)

	switch ctx.GetResponseContentType() {
	case "application/json":
		return ctl.FindOne(c)
	}

	id := c.Param("id")

	logrus.WithFields(logrus.Fields{
		"id": id,
	}).Debug("FindOnePageHandler id from params")

	record := UserModel{}
	err = UserFindOne(id, &record)
	if err != nil {

	}

	if record.ID == 0 {
		logrus.WithFields(logrus.Fields{
			"id": id,
		}).Debug("FindOnePageHandler id record not found")
		return echo.NotFoundHandler(c)
	}

	record.LoadData()

	ctx.Title = record.DisplayName
	ctx.BodyClass = append(ctx.BodyClass, "body-content-findOne")

	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
	mt.Title = record.DisplayName
	mt.Description = record.Biography

	return c.Render(http.StatusOK, "user/findOne", &catu.TemplateCTX{
		Ctx:    ctx,
		Record: &record,
	})
}

type ControllerCfg struct {
}

func NewController(cfg *ControllerCfg) *Controller {
	ctx := Controller{}

	return &ctx
}
