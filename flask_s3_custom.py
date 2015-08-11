import os
import logging
import hashlib
import json
from collections import defaultdict, namedtuple

from flask import url_for as flask_url_for
from flask import current_app
from boto.s3.connection import S3Connection
from boto.s3 import connect_to_region
from boto.exception import S3CreateError, S3ResponseError
from boto.s3.key import Key

logger = logging.getLogger('flask_s3')


def get_path_components(path):
    """
    http://stackoverflow.com/questions/3167154/how-to-split-a-dos-path-into-its-components-in-python
    """
    folders = []
    while True:
        path, folder = os.path.split(path)
        if folder != "":
            folders.append(folder)
        else:
            if path != "":
                folders.append(path)
            break

    folders.reverse()
    return folders


def hash_file(filename):
    """
    Generate a hash for the contents of a file
    """
    hasher = hashlib.sha1()
    with open(filename, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)

    return hasher.hexdigest()


def url_for(folders, endpoint, **values):
    """
    Generates a URL to the given endpoint.

    If the endpoint is for a static resource then an Amazon S3 URL is
    generated, otherwise the call is passed on to `flask.url_for`.

    Because this function is set as a jinja environment variable when
    `FlaskS3.init_app` is invoked, this function replaces
    `flask.url_for` in templates automatically. It is unlikely that this
    function will need to be directly called from within your
    application code, unless you need to refer to static assets outside
    of your templates.
    """
    app = current_app
    if 'S3_BUCKET_NAME' not in app.config:
        raise ValueError("S3_BUCKET_NAME not found in app configuration.")

    my_endpoints = [f.endpoint for f in folders]
    ending_endpoint = endpoint.split('.')[-1]
    if endpoint in my_endpoints or ending_endpoint == 'static':
        scheme = 'http'
        if app.config['S3_USE_HTTPS']:
            scheme = 'https'

        if app.config['S3_URL_STYLE'] == 'host':
            url_format = '%(bucket_name)s.%(bucket_domain)s'
        elif app.config['S3_URL_STYLE'] == 'path':
            url_format = '%(bucket_domain)s/%(bucket_name)s'
        else:
            raise ValueError('Invalid S3 URL style: "%s"'
                             % app.config['S3_URL_STYLE'])

        bucket_path = url_format % {
            'bucket_name': app.config['S3_BUCKET_NAME'],
            'bucket_domain': app.config['S3_BUCKET_DOMAIN'],
        }

        if app.config['S3_CDN_DOMAIN']:
            bucket_path = '%s' % app.config['S3_CDN_DOMAIN']
        urls = app.url_map.bind(bucket_path, url_scheme=scheme)
        return urls.build(endpoint, values=values, force_external=True)
    return flask_url_for(endpoint, **values)


def _bp_static_url(app, blueprint):
    """ builds the absolute url path for a blueprint's static folder """
    urls = app.url_map.bind('')
    u = urls.build("{}.static".format(blueprint.name), values={"filename":""})
    print(u)
    return u


def _get_static_folders(app):
    """ Gets static folders and returns in list of (folder, url) pairs"""
    dirs = [(unicode(app.static_folder), app.static_url_path)]
    if hasattr(app, 'blueprints'):
        blueprints = app.blueprints.values()
        bp_details = lambda x: (x.static_folder, _bp_static_url(app, x))
        dirs.extend([bp_details(x) for x in blueprints if x.static_folder])
    return dirs

def _gather_files(folders, hidden):
    valid_files = defaultdict(list)
    for static_folder, static_url_loc in folders:
        if not os.path.isdir(static_folder):
            logger.warning("WARNING - [%s does not exist]" % static_folder)
        else:
            logger.debug("Checking static folder: %s" % static_folder)
        for root, _, files in os.walk(static_folder):
            files = [os.path.join(root, x) \
                     for x in files if hidden or x[0] != '.']
            if files:
                valid_files[(static_folder, static_url_loc)].extend(files)
    return valid_files


def _path_to_relative_url(path):
    """ Converts a folder and filename into a ralative url path """
    return os.path.splitdrive(path)[1].replace('\\', '/')


def _static_folder_path(static_url, static_folder, static_asset):
    """
    Returns a path to a file based on the static folder, and not on the
    filesystem holding the file.

    Returns a path relative to static_url for static_asset
    """
    # first get the asset path relative to the static folder.
    # static_asset is not simply a filename because it could be
    # sub-directory then file etc.
    if not static_asset.startswith(static_folder):
        raise ValueError("%s static asset must be under %s static folder" %
                         (static_asset, static_folder))
    rel_asset = static_asset[len(static_folder):]
    # Now bolt the static url path and the relative asset location together
    return u'%s/%s' % (static_url.rstrip('/'), rel_asset.lstrip('/'))


def _write_files(app, static_url_loc, static_folder, files, bucket,
                 ex_keys=None, hashes=None):
    """ Writes all the files inside a static folder to S3. """
    new_hashes = []
    static_folder_rel = _path_to_relative_url(static_folder)
    for file_path in files:
        asset_loc = _path_to_relative_url(file_path)
        key_name = _static_folder_path(static_url_loc, static_folder_rel,
                                       asset_loc).strip('/')
        msg = "Uploading %s to %s as %s" % (file_path, bucket, key_name)
        logger.debug(msg)

        exclude = False
        if app.config.get('S3_ONLY_MODIFIED', False):
            file_hash = hash_file(file_path)
            new_hashes.append((key_name, file_hash))

            if hashes and hashes.get(key_name, None) == file_hash:
                exclude = True

        if ex_keys and key_name in ex_keys or exclude:
            logger.debug("%s excluded from upload" % key_name)
        else:
            k = Key(bucket=bucket, name=key_name)
            # Set custom headers
            for header, value in app.config['S3_HEADERS'].iteritems():
                k.set_metadata(header, value)
            k.set_contents_from_filename(file_path)
            k.make_public()
            print("pushing new file {}".format(key_name))

    return new_hashes


def _upload_files(app, files_, bucket, hashes=None):
    new_hashes = []
    for (static_folder, static_url), names in files_.iteritems():
        new_hashes.extend(_write_files(app, static_url, static_folder, names,
                                       bucket, hashes=hashes))
    return new_hashes


def get_bucket(app, user=None, password=None, bucket_name=None,
               location=None):
    user = user or app.config.get('AWS_ACCESS_KEY_ID')
    password = password or app.config.get('AWS_SECRET_ACCESS_KEY')
    bucket_name = bucket_name or app.config.get('S3_BUCKET_NAME')
    if not bucket_name:
        raise ValueError("No bucket name provided.")
    location = location or app.config.get('S3_REGION')

    # connect to s3
    if not location:
        conn = S3Connection(user, password)  # (default region)
    else:
        conn = connect_to_region(location,
                                 aws_access_key_id=user,
                                 aws_secret_access_key=password)

    # get_or_create bucket
    try:
        try:
            bucket = conn.create_bucket(bucket_name)
        except S3CreateError as e:
            if e.error_code == u'BucketAlreadyOwnedByYou':
                bucket = conn.get_bucket(bucket_name)
            else:
                raise e

        bucket.make_public(recursive=False)
    except S3CreateError as e:
        raise e
    return bucket


def create_all(folders, app, include_hidden=False, **kwargs):
    """
    Uploads of the static assets associated with a Flask application to
    Amazon S3.

    All static assets are identified on the local filesystem, including
    any static assets associated with *registered* blueprints. In turn,
    each asset is uploaded to the bucket described by `bucket_name`. If
    the bucket does not exist then it is created.

    Flask-S3 creates the same relative static asset folder structure on
    S3 as can be found within your Flask application.

    Many of the optional arguments to `create_all` can be specified
    instead in your application's configuration using the Flask-S3
    `configuration`_ variables.

    :param app: a :class:`flask.Flask` application object.

    :param user: an AWS Access Key ID. You can find this key in the
                 Security Credentials section of your AWS account.
    :type user: `basestring` or None

    :param password: an AWS Secret Access Key. You can find this key in
                     the Security Credentials section of your AWS
                     account.
    :type password: `basestring` or None

    :param bucket_name: the name of the bucket you wish to server your
                        static assets from. **Note**: while a valid
                        character, it is recommended that you do not
                        include periods in bucket_name if you wish to
                        serve over HTTPS. See Amazon's `bucket
                        restrictions`_ for more details.
    :type bucket_name: `basestring` or None

    :param location: the AWS region to host the bucket in; an empty
                     string indicates the default region should be used,
                     which is the US Standard region. Possible location
                     values include: `'DEFAULT'`, `'EU'`, `'USWest'`,
                     `'APSoutheast'`
    :type location: `basestring` or None

    :param include_hidden: by default Flask-S3 will not upload hidden
        files. Set this to true to force the upload of hidden files.
    :type include_hidden: `bool`

    .. _bucket restrictions: http://docs.amazonwebservices.com/AmazonS3\
    /latest/dev/BucketRestrictions.html

    """
    bucket = get_bucket(app=app, **kwargs)

    # build list of files
    my_folders = [(f.folder, f.url) for f in folders]
    static_folders = _get_static_folders(app)
    all_folders = my_folders + static_folders
    all_files = _gather_files(all_folders, include_hidden)
    logger.debug("All valid files: %s" % all_files)

    if app.config['S3_ONLY_MODIFIED']:
        hashes = get_web_hashes(bucket)
        new_hashes = _upload_files(app, all_files, bucket, hashes=hashes)
        try:
            k = Key(bucket=bucket, name=".file-hashes")
            k.set_contents_from_string(json.dumps(dict(new_hashes)))
        except S3ResponseError as e:
            logger.warn("Unable to upload file hashes: %s" % e)
    else:
        _upload_files(app, all_files, bucket)


def get_web_hashes(bucket):
    try:
        hashes = json.loads(
            Key(bucket=bucket,
                name=".file-hashes").get_contents_as_string())
        return hashes
    except S3ResponseError as e:
        logger.warn("No file hashes found: %s" % e)


def clean(app, **kwargs):
    bucket = get_bucket(app=app, **kwargs)
    hashes = get_web_hashes(bucket)
    if hashes is None:
        print("no hashes available. Bucket not cleaned")

    keys = set(hashes.keys())

    bucket_list = bucket.list()
    for l in bucket_list:
        keyString = str(l.key)
        if keyString == '.file-hashes':
            continue
        if keyString not in keys:
            print("deleting {}".format(keyString))
            l.delete()


def clone(folders, app, **kwargs):
    bucket = get_bucket(app=app, **kwargs)
    hashes = get_web_hashes(bucket)

    my_folders = [(f.folder, f.url) for f in folders]
    static_folders = _get_static_folders(app)
    all_folders = my_folders + static_folders

    # TODO: use hash to see what needs to be updated
    bucket_list = bucket.list()
    for l in bucket_list:
        keyString = str(l.key)
        if keyString == '.file-hashes':
            continue

        # find out which local folder to map to
        for folder_local, folder_url in all_folders:
            folder_comps = get_path_components(folder_url.strip('/'))
            key_comps = get_path_components(keyString.strip('/'))
            # make sure all components match
            for fc, kc in zip(folder_comps, key_comps):
                if fc != kc:
                    break  # some component does not match, continue to next
            else:
                # all components match, this is the right path
                local_root = folder_local
                remaining_path = os.path.join(*key_comps[len(folder_comps):])
                break
        else:
            print("warn: {} does not match a specified folder".format(keyString))
            continue

        # sync local file with web file
        local_path = os.path.join(local_root, remaining_path)
        # if local file already exists, check if the web file has changed
        if os.path.exists(local_path):
            if hashes is None:  # if there are no hashes, then don't write over local files
                continue
            file_hash = hash_file(local_path)
            if hashes.get(keyString, None) == file_hash:  # hash matches, no need to overwrite
                continue
        else:  # if the local file does not exist, check if the folder needs to be created
            local_dir = os.path.dirname(local_path)
            if not os.path.exists(local_dir):
                print("making folder {}".format(local_dir))
                os.makedirs(local_dir)
        # download the file
        print("downloading file {}".format(remaining_path))
        l.get_contents_to_filename(local_path)


class FlaskS3(object):
    """
    The FlaskS3 object allows your application to use Flask-S3.

    When initialising a FlaskS3 object you may optionally provide your
    :class:`flask.Flask` application object if it is ready. Otherwise,
    you may provide it later by using the :meth:`init_app` method.

    :param app: optional :class:`flask.Flask` application object
    :type app: :class:`flask.Flask` or None
    """
    def __init__(self, app=None):
        self._folders = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        An alternative way to pass your :class:`flask.Flask` application
        object to Flask-S3. :meth:`init_app` also takes care of some
        default `settings`_.

        :param app: the :class:`flask.Flask` application object.
        """
        defaults = [('S3_USE_HTTPS', True),
                    ('USE_S3', True),
                    ('USE_S3_DEBUG', False),
                    ('S3_BUCKET_DOMAIN', 's3.amazonaws.com'),
                    ('S3_CDN_DOMAIN', ''),
                    ('S3_USE_CACHE_CONTROL', False),
                    ('S3_HEADERS', {}),
                    ('S3_ONLY_MODIFIED', True),
                    ('S3_URL_STYLE', 'host')]

        for k, v in defaults:
            app.config.setdefault(k, v)

        if app.debug and not app.config['USE_S3_DEBUG']:
            app.config['USE_S3'] = False

        def _url_for(*args, **kwargs):
            return url_for(self.folders, *args, **kwargs)

        if app.config['USE_S3']:
            app.jinja_env.globals['url_for'] = _url_for
        if app.config['S3_USE_CACHE_CONTROL'] and app.config.get('S3_CACHE_CONTROL'):
            cache_control_header = app.config['S3_CACHE_CONTROL']
            app.config['S3_HEADERS']['Cache-Control'] = cache_control_header
        self._app = app

    def create_all(self, *args, **kwargs):
        return create_all(self.folders, self._app, *args, **kwargs)

    def clone(self, *args, **kwargs):
        return clone(self.folders, self._app, *args, **kwargs)

    def clean(self, *args, **kwargs):
        return clean(self._app, *args, **kwargs)

    @property
    def folders(self):
        return self._folders

    @folders.setter
    def folders(self, value):
        _validate_folders(value)
        lfs = [LinkedFolder(endpoint, folder, url) for
               endpoint, folder, url in value]
        self._folders = lfs

LinkedFolder = namedtuple('LinkedFolder', ['endpoint', 'folder', 'url'])

def _validate_folders(folders):
    # TODO: validate the folder struct
    pass
