<?php
    /**
    * Copyright (c) 2005 Richard Heyes (http://www.phpguru.org/)
    *
    * All rights reserved.
    *
    * This script is free software; you can redistribute it and/or modify
    * it under the terms of the GNU General Public License as published by
    * the Free Software Foundation; either version 2 of the License, or
    * (at your option) any later version.
    *
    * The GNU General Public License can be found at
    * http://www.gnu.org/copyleft/gpl.html.
    *
    * This script is distributed in the hope that it will be useful,
    * but WITHOUT ANY WARRANTY; without even the implied warranty of
    * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    * GNU General Public License for more details.
    */

    /**
    * Implements an object which iterates over each line in a file.
    *
    * Eg:
    *
    * foreach(new FileIterator('myFile.txt') as $line) {
    *     // Do stuff with $line...
    * }
    *
    * Or:
    *
    * foreach(new FileIterator('myFile.txt', 2048) as $key => $line) { // Possibly long lines
    *     $lineNum = $key + 1;
    *
    *     // Do stuff...
    * }
    *
    */

    class FileIterator implements Iterator
    {
        /**
        * Name of file
        * @var string
        */
        private $filename;


        /**
        * Size of read buffer
        * @var int
        */
        private $buffer;


        /**
        * File pointer
        * @var resource
        */
        private $fp;


        /**
        * Current line of file
        * @var string
        */
        private $current;


        /**
        * Current line number of file
        * @var int
        */
        private $key;


        /**
        * Whether current element is valid or not
        */
        private $valid;


        /**
        * Constructor. Takes the name of the file
        *
        * @param string $filename Name of file to go thru
        */
        public function __construct($filename, $buffer = 1024)
        {
            $this->filename = $filename;
            $this->buffer   = $buffer;
            $this->key      = -1;

            if (file_exists($filename) AND is_readable($filename)) {
                $this->fp = fopen($filename, 'rb');
            }
        }


        /**
        * Iterator::current() - Returns the current line of the file.
        *
        * @return string Current line of file
        */
        public function current()
        {
            return $this->current;
        }


        /**
        * Iterator::key() - Returns the current "key". In this instance, key() + 1 would
        * give you the current line number.
        *
        * @return string Current elements key
        */
        public function key()
        {
            return $this->key;
        }


        /**
        * Iterator::next() - Advances the iterator to the next "element"
        */
        public function next()
        {
            if (is_resource($this->fp)) {
                if (!feof($this->fp)) {
                    $this->key++;
                    $this->current = fgets($this->fp, $this->buffer);
                    $this->valid   = true;

                } else {
                    $this->valid = false;
                }
            }
        }


        /**
        * Iterator::rewind() - Resets the iterator to the "beginning"
        */
        public function rewind()
        {
            if (is_resource($this->fp)) {
                $this->key = -1;
                fseek($this->fp, 0);

                $this->next();
            }
        }


        /**
        * Iterator::valid() - Returns true/false as to whether a call to current()
        * is valid/possible or not.
        *
        * @return bool Whether current element is valid or not
        */
        public function valid()
        {
            return $this->valid;
        }
    }
?>