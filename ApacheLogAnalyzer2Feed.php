<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * ApacheLogAnalyzer2Feed - Apache log file analyzer with feed output
 *
 * Copyright (c) 2007 Simone Carletti
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * If you have any questions or comments, please email:
 * Simone Carletti
 * weppos@weppos.net
 * http://www.simonecarletti.com/
 *
 * @category        Tool
 * @package         ApacheLogAnalyzer2Feed
 * @author          Simone Carletti <weppos@weppos.net>
 * @copyright       2007 The Authors
 * @license         http://creativecommons.org/licenses/LGPL/2.1/ LGPL License 2.1
 * @version         SVN: $Id: ApacheLogAnalyzer2Feed.php 3 2007-05-31 13:11:29Z weppos $
 * @link            http://www.simonecarletti.com/code/apachelog2feed ApacheLogAnalyzer2Feed Site
 */


/**
 * ApacheLogAnalyzer2Feed
 *
 * ApacheLogAnalyzer2Feed is a really powerful class
 * to analyze Apache Web Server log files.
 * Analysis results are converted into a feed to let users subscribe with a feed reader.
 *
 * Each log file can be analyzed/filtered with a filter chain based on log data.
 * For instance, you can select only rows where IP is 123.123.123.123,
 * user agent contains the word 'GoogleBot' (regular expression pattern),
 * request is made for page 'mt-search.cgi' and so on.
 *
 * You can append how many filter you need and run log parsing.
 *
 * Results are converted into a feed. The feed can be generated on the fly
 * or stored into a static XML file (recommended).
 *
 * This class is extensible.
 * You can extends it via PHP5 object oriented architecture.
 * For instance, you can adds more filter callbacks or change feed generator handler.
 *
 * @category        Tool
 * @package         ApacheLogAnalyzer2Feed
 * @author          Simone Carletti <weppos@weppos.net>
 * @copyright       2007 The Authors
 * @license         http://creativecommons.org/licenses/LGPL/2.1/ LGPL License 2.1
 * @version         SVN: $Id: ApacheLogAnalyzer2Feed.php 3 2007-05-31 13:11:29Z weppos $
 * @link            http://www.simonecarletti.com/code/apachelog2feed ApacheLogAnalyzer2Feed Site
 */
class ApacheLogAnalyzer2Feed
{
    /** AND mode */
    Const FILTER_MODE_AND = '_testFiltersModeAnd';
    /** OR mode */
    Const FILTER_MODE_OR = '_testFiltersModeOr';

    /** X == Y */
    Const COMPARISON_IS = 'IS';
    /** X != Y */
    Const COMPARISON_ISNOT = 'ISNOT';
    /** X includes Y */
    Const COMPARISON_LIKE = 'INC';
    /** X doesn't include Y */
    Const COMPARISON_NOTLIKE = 'EXC';

    /** Common Apache Log Format */
    Const LOG_FORMAT_COMMON = '%h %l %u %t \"%r\" %>s %b';
    /** Combined Apache Log Format */
    Const LOG_FORMAT_COMBINED = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"';

    /** Name */
    const NAME = 'ApacheLogAnalyzer2Feed';
    /** Package */
    const PACKAGE = 'Tools';
    /** Author */
    const AUTHOR = 'Simone Carletti <weppos@weppos.net>';
    /** Version */
    const VERSION = '0.1.0';
    /** Status */
    const STATUS = 'beta';
    /** Build */
    const BUILD = '$Rev: 3 $';

    /** SVN ID */
    const SVN_ID = '$Id: ApacheLogAnalyzer2Feed.php 3 2007-05-31 13:11:29Z weppos $';
    /** SVN Revision */
    const SVN_REVISION = '$Rev: 3 $';
    /** SVN Date  */
    const SVN_DATE = '$Date: 2007-05-31 15:11:29 +0200 (Thu, 31 May 2007) $';

    /**
     * Path to source log file
     *
     * @var     string
     * @access  protected
     */
    protected $_source;

    /**
     * Path to target file
     *
     * @var     null|string
     * @access  protected
     */
    protected $_target = null;

    /**
     * Log filters
     *
     * @var     array
     * @access  protected
     */
    protected $_filters = array();

    /**
     * Log filter callback function
     *
     * @var     string
     * @access  protected
     */
    protected $_filterCallback = self::FILTER_MODE_AND;

    /**
     * Apache Log Format
     *
     * @var     null|string
     * @link    http://httpd.apache.org/docs/1.3/logs.html#accesslog Apache 1.3 Log Docs
     * @access  protected
     */
    protected $_logFormat = null;

    /**
     * Log limit, the maximum nuber of rows to be processes
     *
     * @var     int
     * @access  protected
     */
    protected $_logLimit = 100000;

    /**
     * FileIterator instance
     *
     * @var     FileIterator
     * @access  protected
     */
    protected $_fileIterator = null;

    /**
     * ApacheLogParser instance
     *
     * @var     ApacheLogParser
     * @access  protected
     */
    protected $_apacheLogParser = null;


    /**
     * ApacheLogAnalyzer2Feed constructor
     *
     * This constructor uses internal functions to sets given arguments.
     * Please note that some of these functions may throw an exception.
     *
     * @param   string          $source
     * @param   null|string     $target
     * @param   null|string     $logFormat
     */
    public function __construct($source, $target = null, $logFormat = null)
    {
        $this->setSource($source);
        if (!is_null($target)) $this->setTarget($target);
        $this->setLogFormat(is_null($logFormat) ? self::LOG_FORMAT_COMBINED : $logFormat);
    }

    /**
     * Add a new filter
     *
     * @param   string  $field
     * @param   string  $value
     * @param   string  $comparison
     * @return  void
     */
    public function addFilter($field, $value, $comparison = null)
    {
        $filterField = (string) $field;
        $filterValue = (string) $value;
        $filterComparison = is_null($comparison) ? self::COMPARISON_IS : $comparison; // may be in the future I will support it!
        $this->_filters[] = array($filterField, $filterValue, $filterComparison);
    }

    /**
     * Returns log filters
     *
     * @param   null|string $index
     * @return  mixed
     */
    public function getFilters($index)
    {
        if ($index === null)
            return $this->_filters;
        elseif (isset($this->_filters[$index]))
            return $this->_filters[$index];
        else
            return null;
    }

    /**
     * Returns log format
     *
     * @return  string
     */
    public function getLogFormat()
    {
        return $this->_logFormat;
    }

    /**
     * Returns log limit
     *
     * @return  int
     */
    public function getLogLimit()
    {
        return $this->_logLimit;
    }

    /**
     * Returns log source filename
     *
     * @return  string
     */
    public function getSource()
    {
        return $this->_source;
    }

    /**
     * Returns target filename
     *
     * @return  null|string
     */
    public function getTarget()
    {
        return $this->_target;
    }

    /**
     * Run parse/filter/generation batch
     *
     * @return  void
     */
    public function run()
    {
        $iterator = $this->_getFileIterator();
        $parser = $this->_getApacheLogParser();

        /**
         * @see FeedCreator
         */
        require_once 'FeedCreator.php';

        $feed = $this->_getFeedHandler();
        foreach ($iterator as $ii => $row) {
            if ($ii >= $this->getLogLimit()) break;

            $data = $parser->parse($row);
            $filterMethodName = $this->_getFilterMethodName();

            if (call_user_func(array(&$this, $filterMethodName), $data)) {
                $this->_addFeedItem($feed, $data);
                // print('<pre>'); print_r($data); print('</pre>');
            }
        }

        if ($this->getTarget() == null) {
            $this->_displayFeed($feed);
        }
        else {
            $this->_saveFeed($feed);
        }
    }

    /**
     * Sets Apache Log formats
     *
     * The log format is one of the most important thing to bear in mind
     * when using this tool.
     * If the log format is invalid the parser will not be able
     * to analyze log data.
     *
     * @param   string  $format
     * @return  void
     */
    public function setLogFormat($format)
    {
        $this->_logFormat = (string) $format;
    }

    /**
     * Sets log limit
     *
     * @param   int     $limit
     * @return  void
     * @throws  Exception
     */
    public function setLogLimit($limit)
    {
        if (!is_int($limit))
            throw new Exception(sprintf('%s::%s expects parameter $limit to be an integer',
                                        __CLASS__,
                                        __FUNCTION__));

        $this->_logLimit = $limit;
    }

    /**
     * Sets source log file
     *
     * @param   string  $fileName
     * @return  void
     * @throws  Exception
     */
    public function setSource($fileName)
    {
        if (!file_exists($fileName) || !is_readable($fileName))
            throw new Exception("Either source file '$fileName' is invalid or cannot be read");

        $this->_source = $fileName;
    }

    /**
     * Sets filter callback function
     *
     * @param   string  $callback
     * @return  void
     * @throws  Exception
     */
    public function setFilterCallback($callback)
    {
        if (!is_callable(array($this, $callback)))
            throw new Exception(sprintf('%s is not a valid callable function', $callback));

        $this->_filterCallback = $callback;
    }

    /**
     * Sets target file
     *
     * @param   string  $fileName
     * @return  void
     */
    public function setTarget($fileName)
    {
        $this->_target = $fileName;
    }


    /**
     * Generates an unique hash for a single item
     *
     * This function is useful to generate an unique log row identifier.
     * Can be used, for example, to compose feed item GUID string.
     *
     * @param   string  $data
     * @return  string  Unique hash
     * @access  protected
     */
    protected function _generateItemHash($data)
    {
        return md5(serialize($data));
    }

    /**
     * Returns FileIterator instance
     *
     * @return  FileIterator    FileIterator instance
     * @access  protected
     */
    protected function _getFileIterator()
    {
        /**
         * @see FileIterator
         */
        require_once 'FileIterator.php';

        if (is_null($this->_fileIterator)) {
            $this->_fileIterator = new FileIterator($this->getSource());
        }

        return $this->_fileIterator;
    }

    /**
     * Returns ApacheLogParser instance
     *
     * @return  ApacheLogParser ApacheLogParser instance
     * @access  protected
     */
    protected function _getApacheLogParser()
    {
        /**
         * @see ApacheLogParser
         */
        require_once 'ApacheLogParser.php';

        if (is_null($this->_apacheLogParser)) {
            $this->_apacheLogParser = new ApacheLogRegex($this->getLogFormat());
        }

        return $this->_apacheLogParser;
    }


    /**
     * Returns filter method name to be called
     * according to filter mode.
     *
     * @return  string
     * @access  protected
     */
    protected function _getFilterMethodName()
    {
        /*
        switch ($this->_filterCallback) {
            default:
                $name = $this->_filterCallback;
        }
        */

        return $this->_filterCallback;
    }

    /**
     * Tests current log row against a single filter
     *
     * This method currently tests only a simple string or regexp pattern.
     *
     * @param   array   $parsedLogData
     * @param   array   $filter
     * @return  bool
     * @throws  Exception
     * @access  protected
     */
    protected function _testFilter($parsedLogData, $filter)
    {
        if (is_null($filter))
            return true;
        if (count($filter) == 2)
            throw new Exception('Invalid filter format');
        if (!is_array($parsedLogData))
            return false;

        list($field, $value, $comparison) = $filter;

        // does field exist?
        if (!isset($parsedLogData[$field]))
            return false;

        // is a regexp?
        $isRegexp = false;
        if (strpos($value, 'regexp:') !== false) {
            $isRegexp = true;
            $value = str_replace('regexp:', '', $value);
        }

        if ($isRegexp) {
            $pattern = str_replace('#', '\#', $value); // escape delimiter
            return preg_match("#$pattern#", $parsedLogData[$field]);
        }
        else {
            return $parsedLogData[$field] == $value;
        }
    }

    /**
     * Tests current log row against all given filters.
     *
     * Filters are joined according to OR logic operator.
     *
     * @param   array   $parsedLogData
     * @return  bool    TRUE if at least one filter returned TRUE,
     *                  FALSE otherwise.
     * @access  protected
     * @internal        Need to be improved for huge log files
     */
    protected function _testFiltersModeOr($parsedLogData)
    {
        $filtersCount = count($this->getFilters(null));
        if (!count($filtersCount) > 0)
            return true; // no filters, test passed!

        $ii = 0;
        while ($ii < $filtersCount && // check array length
               !$this->_testFilter($parsedLogData, $this->getFilters($ii)) // current filter test failed
               )
        {
            $ii++; // next filter
        }

        return $ii < $filtersCount; // at least one filter returned true
    }

    /**
     * Tests current log row against all given filters.
     *
     * Filters are joined according to AND logic operator.
     *
     * @param   array   $parsedLogData
     * @param   int     $filterIndex
     * @return  bool    TRUE if any filter returned TRUE,
     *                  FALSE otherwise.
     * @access  protected
     * @internal        Need to be improved for huge log files
     */
    protected function _testFiltersModeAnd($parsedLogData)
    {
        $filtersCount = count($this->getFilters(null));
        if (!count($filtersCount) > 0)
            return true; // no filters, test passed!

        $ii = 0;
        while ($ii < $filtersCount && // check array length
               $this->_testFilter($parsedLogData, $this->getFilters($ii)) // current filter test failed
               )
        {
            $ii++; // next filter
        }

        return $ii == $filtersCount; // all filters returned true
    }


    /**
     * Create and returns a feed handler
     *
     * This method can easily be extended with a custom feed handler.
     *
     * @return  mixed   Feed handler instance/reference
     * @access  protected
     */
    protected function _getFeedHandler()
    {
        $filtersCount = count($this->getFilters(null));

        $title = sprintf("Log %s filtered by %s",
                               $this->getSource(),
                               $filtersCount ? $filtersCount . ' filters' : 'no filter'
                               );
        $description = print_r($this->getFilters(null), true); // can be improved

        $feed = new UniversalFeedCreator();
        $feed->title = $title;
        $feed->link = $_SERVER['PHP_SELF']; // needs to be improved!
        $feed->description = $description;

       return $feed;
    }

    /**
     * Append a feed item to current feed handler
     *
     * This method can easily be extended with a custom feed handler.
     *
     * @param   mixed   $feedHandler
     * @param   array   $data
     * @return  void
     * @access  protected
     */
    protected function _addFeedItem($feedHandler, $data)
    {
        $data = (array) $data; // just to be sure it is an array

        $title  = isset($data['Remote-Host']) ? $data['Remote-Host'] : '';
        $title .= isset($data['Remote-User']) ? ' ' . $data['Remote-User'] : '';
        $title .= isset($data['Request']) ? ' ' . $data['Request'] : '';

        $time = isset($data['Time']) ? $data['Time'] : null;
        $time = !is_null($time) ? strtotime(str_replace(array('[', ']'), '', $time)) : null;

        $item = new FeedItem();
        $item->title = $title;
        $item->link = $_SERVER['PHP_SELF']; // needs to be improved!
        $item->description = print_r($data, true); // can be improved
        if (!is_null($time)) $item->date = date(DATE_RSS, $time);
        $item->guid = $this->_generateItemHash($data);

        $feedHandler->addItem($item);
    }

    /**
     * Creates the feed and saves it
     *
     * This method can easily be extended with a custom feed handler.
     *
     * @param   mixed   $feedHandler
     * @return  void
     * @access  protected
     */
    protected function _saveFeed($feedHandler)
    {
        $feedHandler->saveFeed("RSS2.0", $this->getTarget(), false);
    }

    /**
     * Prints out the feed
     *
     * This method can easily be extended with a custom feed handler.
     *
     * @param   mixed   $feedHandler
     * @return  void
     * @access  protected
     */
    protected function _displayFeed($feedHandler)
    {
        $feedHandler->outputFeed("RSS2.0");
    }
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
