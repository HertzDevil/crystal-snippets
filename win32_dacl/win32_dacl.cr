require "./c/*"

module Win32DACL
  def self.file_permissions(handle)
    status = LibC.GetSecurityInfo(
      handle,
      LibC::SE_OBJECT_TYPE::FILE_OBJECT,
      LibC::OWNER_SECURITY_INFORMATION | LibC::GROUP_SECURITY_INFORMATION | LibC::DACL_SECURITY_INFORMATION,
      out owner_sid,
      out group_sid,
      out dacl,
      nil,
      out security_descriptor,
    )
    raise IO::Error.from_os_error("GetSecurityInfo", WinError.new(status)) unless status == 0

    begin
      ::File::Permissions.new(
        permissions_from_dacl(dacl, owner_sid) << 6 |
        permissions_from_dacl(dacl, group_sid) << 3 |
        permissions_from_dacl(dacl, world_sid)
      )
    ensure
      LibC.LocalFree(security_descriptor)
    end
  end

  private def self.permissions_from_dacl(dacl, sid)
    LibC.BuildTrusteeWithSidW(out trustee, sid)
    if LibC.GetEffectiveRightsFromAclW(dacl, pointerof(trustee), out access_rights) != 0
      raise RuntimeError.from_winerror("GetEffectiveRightsFromAclW")
    end

    permissions = 0_i16
    permissions |= 1 if access_rights.includes?(LibC::ACCESS_MASK::FILE_GENERIC_EXECUTE)
    permissions |= 2 if access_rights.includes?(LibC::ACCESS_MASK::FILE_GENERIC_WRITE)
    permissions |= 4 if access_rights.includes?(LibC::ACCESS_MASK::FILE_GENERIC_READ)
    permissions
  end

  private class_getter world_sid : LibC::SID* do
    sid = Pointer(UInt8).malloc(LibC::SECURITY_MAX_SID_SIZE).as(LibC::SID*)
    size = LibC::DWORD.new!(LibC::SECURITY_MAX_SID_SIZE)
    if LibC.CreateWellKnownSid(LibC::WELL_KNOWN_SID_TYPE::WinWorldSid, nil, sid, pointerof(size)) == 0
      raise RuntimeError.from_winerror("CreateWellKnownSid")
    end
    sid
  end

  def self.readable?(path) : Bool
    check_rw_access(path, false)
  end

  def self.writable?(path) : Bool
    check_rw_access(path, true)
  end

  private def self.check_rw_access(path, write = false)
    winpath = Crystal::System.to_wstr(path)

    handle = LibC.CreateFileW(
      winpath,
      LibC::ACCESS_MASK::FILE_READ_ATTRIBUTES | LibC::ACCESS_MASK::READ_CONTROL,
      LibC::DEFAULT_SHARE_MODE,
      nil,
      LibC::OPEN_EXISTING,
      LibC::FILE_FLAG_BACKUP_SEMANTICS,
      LibC::HANDLE.null
    )
    return false if handle == LibC::INVALID_HANDLE_VALUE

    begin
      if write
        attributes = LibC.GetFileAttributesW(winpath)
        return false if attributes == LibC::INVALID_FILE_ATTRIBUTES
        return false if attributes.bits_set?(LibC::FILE_ATTRIBUTE_READONLY)
      end

      status = LibC.GetSecurityInfo(handle, LibC::SE_OBJECT_TYPE::FILE_OBJECT, LibC::DACL_SECURITY_INFORMATION, nil, nil, out dacl, nil, out security_descriptor)
      raise IO::Error.from_os_error("GetSecurityInfo", WinError.new(status)) unless status == 0

      begin
        LibC.BuildTrusteeWithSidW(out trustee, process_sid)
        if LibC.GetEffectiveRightsFromAclW(dacl, pointerof(trustee), out access_rights) != 0
          raise RuntimeError.from_winerror("GetEffectiveRightsFromAclW")
        end
        access_rights.includes?(write ? LibC::ACCESS_MASK::FILE_GENERIC_WRITE : LibC::ACCESS_MASK::FILE_GENERIC_READ)
      ensure
        LibC.LocalFree(security_descriptor)
      end
    ensure
      LibC.CloseHandle(handle)
    end
  end

  private class_getter process_sid : LibC::SID* do
    LibC.GetTokenInformation(LibC::GetCurrentProcessToken, LibC::TOKEN_INFORMATION_CLASS::TokenOwner, nil, 0, out byte_size)
    buf = Pointer(UInt8).malloc(byte_size).as(LibC::TOKEN_OWNER*)
    LibC.GetTokenInformation(LibC::GetCurrentProcessToken, LibC::TOKEN_INFORMATION_CLASS::TokenOwner, buf, byte_size, out _)
    buf.value.owner
  end
end

File.open("#{__DIR__}/../README.md") do |f|
  p!(
    Win32DACL.file_permissions(LibC::HANDLE.new(f.fd)),
    Win32DACL.readable?(f.path),
    Win32DACL.writable?(f.path),
  )
end
