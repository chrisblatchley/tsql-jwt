----------------------------
-- Complete SQL Script --
----------------------------

-- XML to JSON Conversion
if object_id('dbo.XmlToJson', 'FN') is not null
    drop function dbo.XmlToJson;
go

create function dbo.XmlToJson(@xmldata xml)
returns nvarchar(max)
as
begin
    declare @json nvarchar(max);

    -- Convert XML nodes to JSON format
    select @json = concat(@json, ',{'
        + stuff((
            select ',"'
                    + b.c.value('local-name(.)', 'nvarchar(max)')
                    + '":"'
                    + b.c.value('text()[1]', 'nvarchar(max)')
                    + '"'
            from @xmldata.nodes('/root/*') x(a)
            cross apply a.nodes('*') b(c)
            for xml path(''), type
        ).value('(./text())[1]', 'nvarchar(max)'), 1, 1, '')
        + '}')
    from @xmldata.nodes('/root/*') x(a);

    -- Remove leading comma and return the JSON result
    return stuff(@json, 1, 1, '');
end;
go

grant execute on dbo.XmlToJson to public;
go


-- HMAC Encryption
create or alter function dbo.hmac (
	@key	varbinary(max),
	@data	varbinary(max),
	@algo	varchar(20)
)
returns varbinary(64)
as
begin
	declare @ipad bigint = cast(0x3636363636363636 as bigint);
	declare @opad bigint = cast(0x5C5C5C5C5C5C5C5C as bigint);
	declare @i varbinary(64) = 0x;
	declare @o varbinary(64) = 0x;
	declare @pos int = 1;

	if len(@key) > 64
		set @key = hashbytes(@algo, @key);
	else
		set @key = @key + replicate(0x00, 64 - len(@key)); -- Pad to 64 bytes

	while @pos <= 57
	begin
		set @i = @i + (substring(@key, @pos, 8) ^ @ipad);
		set @pos = @pos + 8;
	end

	set @pos = 1;

	while @pos <= 57
	begin
		set @o = @o + (substring(@key, @pos, 8) ^ @opad);
		set @pos = @pos + 8;
	end

	return hashbytes(@algo, @o + hashbytes(@algo, @i + @data));
end;
go

grant execute on dbo.hmac to public;
go


-- Base64 Encoding
if object_id('dbo.Base64', 'FN') is not null
    drop function dbo.Base64;
go

create function dbo.Base64 (
    @data varbinary(max),
    @url_safe bit
)
returns varchar(max)
as
begin
    declare @base64string varchar(max);

    -- Base64 encode the binary data using JSON conversion
    select @base64string = col
    from openjson((
        select col
        from (select @data col) T
        for json auto
    )) with (col varchar(max));

    -- Make Base64 URL-safe if required
    if @url_safe = 1
    begin
        select @base64string = replace(@base64string, '+', '-');
        select @base64string = replace(@base64string, '/', '_');
    end

    return @base64string;
end;
go

grant execute on dbo.Base64 to public;
go


-- JSON Web Token (JWT) Creation
create or alter function dbo.JWT_Encode(
	@json_header	varchar(max),
	@json_payload	varchar(max),
	@secret			varchar(max)
)
returns varchar(max)
as
begin
	declare @header		varchar(max),
			@data		varchar(max),
			@signature	varchar(max);

	-- Base64 encode json header
	select @header = dbo.Base64(convert(varbinary(max), @json_header), 1);

	-- Base64 encode json payload
	select @data = dbo.Base64(convert(varbinary(max), @json_payload), 1);

	-- Generate signature using HMAC SHA256
	select @signature = dbo.hmac(
		convert(varbinary(max), @secret),
		convert(varbinary(max), @header + '.' + @data),
		'SHA2_256'
	);

	-- Base64 encode signature
	select @signature = dbo.Base64(@signature, 1);

	return @header + '.' + @data + '.' + @signature;
end;
go

grant execute on dbo.JWT_Encode to public;
go


-- Example Usage
select	dbo.JWT_Encode(
			dbo.XmlToJson((select 'HS256' alg, 'JWT' typ for xml path, root)),
			dbo.XmlToJson((select 'chris' name, 'true' admin for xml path, root)),
			'secret'
		);

select	dbo.JWT_Encode(
			(select 'HS256' alg, 'JWT' typ for json path, without_array_wrapper),
			(select 'brian' name, 'true' admin for json path, without_array_wrapper),
			'secret'
		);

select	dbo.JWT_Encode(
			'{"alg":"HS256","typ":"JWT"}',
			'{"name":"brian","admin":"true"}',
			'secret'
		);
